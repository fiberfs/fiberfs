/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

enum fbr_cstore_entry_type
_parse_url(const char *url, size_t url_len, const char *etag, size_t etag_len, size_t *offset)
{
	assert_dev(url);
	assert_dev(etag);
	assert_dev(offset);

	*offset = 0;

	if (!url_len || !etag_len) {
		return FBR_CSTORE_FILE_NONE;
	}

	for (size_t i = 0; i < url_len; i++) {
		if (i && url[i - 1] == '/' && url[i] == '.') {
			if (!strcmp(&url[i], ".fiberfsroot")) {
				assert_dev(i + 12 == url_len);
				return FBR_CSTORE_FILE_ROOT;
			} else if (!strncmp(&url[i], ".fiberfsindex.", 14)) {
				i += 14;
				if (i >= url_len) {
					return FBR_CSTORE_FILE_NONE;
				}

				if (!strncmp(&url[i], etag, etag_len)) {
					if (i + etag_len == url_len) {
						return FBR_CSTORE_FILE_INDEX;
					}
				}

				return FBR_CSTORE_FILE_NONE;
			} else if (!strncmp(&url[i], ".fiberfs", 8)) {
				return FBR_CSTORE_FILE_NONE;
			}
		} else if (url[i] == '.') {
			if (!strncmp(&url[i + 1], etag, etag_len)) {
				i += 2 + etag_len;
				if (i >= url_len) {
					return FBR_CSTORE_FILE_NONE;
				} else if (url[i - 1] != '.') {
					continue;
				}

				if (url[i] < '0' || url[i] > '9') {
					continue;
				}

				*offset = fbr_parse_ulong(&url[i], url_len - i);
				if (!offset) {
					if (url[i] != '0' || i + 1 < url_len) {
						continue;
					}
				}

				return FBR_CSTORE_FILE_CHUNK;
			}
		}
	}

	return FBR_CSTORE_FILE_NONE;
}

int
fbr_cstore_url_write(struct fbr_cstore_worker *worker, struct chttp_context *request)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(request);
	assert(request->state == CHTTP_STATE_BODY);
	assert_zero(request->chunked);
	chttp_addr_connected(&request->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	size_t offset;
	size_t length = request->length;
	assert(length);

	const char *url = chttp_header_get_url(request);
	assert(url);
	size_t url_len = strlen(url);

	const char *host = chttp_header_get(request, "Host");
	assert(host);
	size_t host_len = strlen(host);

	const char *etag = chttp_header_get(request, "ETag");
	assert(etag);
	size_t etag_len = strlen(etag);
	if (etag_len && etag[etag_len - 1] == '\"') {
		etag_len--;
	}
	if (etag[0] == '\"') {
		etag++;
		etag_len--;
	}

	fbr_id_t etag_id = fbr_id_parse(etag, etag_len);
	if (!etag_id) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR etag");
		return 1;
	}

	enum fbr_cstore_entry_type file_type = _parse_url(url, url_len, etag, etag_len, &offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url");
		return 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE %s %s %s", host, url, path);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, length, path, 1);
	if (!entry) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR loading state");
		return 1;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	size_t bytes = 0;
	int fallback_rw = 0;

	if (cstore->cant_splice) {
		fallback_rw = 1;
	}

	while (!fallback_rw && bytes < length) {
		ssize_t ret = splice(request->addr.sock, NULL, fd, NULL, length, SPLICE_F_MOVE);
		if (ret < 0) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR splice %d %s",
				errno, strerror(errno));

			if (bytes == 0 && errno == EINVAL) {
				cstore->cant_splice = 1;
				fallback_rw = 1;
			}

			break;
		} else if (ret == 0) {
			break;
		}

		bytes += (size_t)ret;
	}

	while (fallback_rw && bytes < length) {
		// TODO needs to be bigger
		char buffer[4096];
		size_t ret = chttp_body_read(request, buffer, sizeof(buffer));
		if (request->error) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR body %s",
				chttp_error_msg(request));
			break;
		} else if (ret == 0) {
			break;
		}

		ret = fbr_sys_write(fd, buffer, ret);
		if (ret == 0) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR write()");
			break;
		}

		bytes += (size_t)ret;
	}

	assert_zero(close(fd));

	if (bytes != length) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR bytes (%zu)", bytes);

		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);

		if (!request->error) {
			chttp_error(request, CHTTP_ERR_NETWORK);
		}

		return 1;
	}

	if (!fallback_rw) {
		request->length = 0;
		request->state = CHTTP_STATE_IDLE;
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE wrote %zu bytes (%s)", bytes,
		fallback_rw ? "read/write" : "splice");

	struct fbr_cstore_metadata metadata;
	fbr_ZERO(&metadata);
	metadata.etag = etag_id;
	metadata.size = length;
	metadata.offset = offset;
	metadata.type = file_type;
	assert(url_len < sizeof(metadata.path));
	memcpy(metadata.path, url, url_len + 1);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	// TODO stats

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	return 0;
}
