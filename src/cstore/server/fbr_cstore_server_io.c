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
#include <sys/sendfile.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

static enum fbr_cstore_entry_type
_parse_url(const char *url, size_t url_len, const char *etag, size_t etag_len, size_t *offset)
{
	assert_dev(url);
	assert_dev(offset);

	*offset = 0;

	if (!url_len) {
		return FBR_CSTORE_FILE_NONE;
	}

	for (size_t i = 0; i < url_len; i++) {
		if (i && url[i - 1] == '/' && url[i] == '.') {
			if (!strcmp(&url[i], ".fiberfsroot")) {
				assert_dev(i + 12 == url_len);
				return FBR_CSTORE_FILE_ROOT;
			} else if (!strncmp(&url[i], ".fiberfsindex.", 14)) {
				i += 14;
				if (i >= url_len || !etag_len) {
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
			if (!etag_len) {
				continue;
			}

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
				if (!*offset) {
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

	if (request->chunked) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR chunked");
		return 1;
	}

	size_t offset;
	size_t length = request->length;
	assert(length);

	const char *url = chttp_header_get_url(request);
	assert(url);
	size_t url_len = strlen(url);

	const char *host = chttp_header_get(request, "Host");
	if (!host) {
		host = "";
	}
	size_t host_len = strlen(host);

	const char *etag = chttp_header_get(request, "ETag");
	if (!etag) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR no etag");
		return 1;
	}

	size_t etag_len = strlen(etag);
	if (etag_len >= 2 && etag[etag_len - 1] == '\"' && etag[0] == '\"') {
		etag++;
		etag_len -= 2;
	}

	fbr_id_t etag_id = fbr_id_parse(etag, etag_len);
	if (!etag_id) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR etag");
		return 1;
	}

	int unique = 0;
	const char *if_none_match = chttp_header_get(request, "If-None-Match");
	if (if_none_match) {
		if (!strcmp(if_none_match, "*")) {
			unique = 1;
		} else {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR if-none-match");
			return 1;
		}
	}

	fbr_id_t etag_match = 0;
	const char *if_match = chttp_header_get(request, "If-Match");
	if (if_match) {
		size_t if_match_len = strlen(if_match);
		if (if_match_len >= 2 && if_match[if_match_len - 1] == '\"' &&
		    if_match[0] == '\"') {
			if_match++;
			if_match_len -= 2;
		}

		etag_match = fbr_id_parse(if_match, if_match_len);
		if (!etag_match || unique) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR if-match");
			return 1;
		}
	}

	enum fbr_cstore_entry_type file_type = _parse_url(url, url_len, etag, etag_len, &offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url");
		return 1;
	}

	switch (file_type) {
		case FBR_CSTORE_FILE_CHUNK:
		case FBR_CSTORE_FILE_INDEX:
			if (!unique || etag_match) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_WRITE ERROR need unique");
				return 1;
			}
			break;
		case FBR_CSTORE_FILE_ROOT:
			if (!unique && !etag_match) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_WRITE ERROR root missing conditions");
				return 1;
			}
			break;
		default:
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url type");
			return 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE %s %s %s %s unique: %d match: %lu",
		fbr_cstore_type_name(file_type) ,host, url, path, unique, etag_match);

	// TODO if root, we need to goto s3 first

	struct fbr_cstore_entry *entry = NULL;
	if (unique) {
		entry = fbr_cstore_io_get_loading(cstore, hash, length, path, 1);
		if (!entry) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR loading state");
			return 1;
		}
	} else {
		assert_dev(etag_match);
		assert_dev(file_type == FBR_CSTORE_FILE_ROOT);

		entry = fbr_cstore_get(cstore, hash);
		if (entry) {
			fbr_cstore_reset_loading(entry);
		} else {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
				"URL_WRITE ERROR loading state 2");
			return 1;
		}
	}

	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	if (etag_match) {
		struct fbr_cstore_metadata metadata;
		fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
		int ret = fbr_cstore_metadata_read(path, &metadata);
		if (ret) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR metadata");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, entry);
			return 1;
		}

		if (metadata.etag != etag_match) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
				"URL_WRITE ERROR bad version want: %lu got: %lu",
				etag_match, metadata.etag);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, entry);
			return 1;
		}
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE conditions passed");

	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	size_t bytes = fbr_cstore_s3_splice(cstore, request, fd, length);

	assert_zero(close(fd));

	if (bytes != length) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR bytes (%zu)", bytes);

		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);

		if (!request->error) {
			chttp_error(request, CHTTP_ERR_NETWORK);
		}

		return 1;
	} else {
		assert_dev(request->state >= CHTTP_STATE_IDLE);
		assert_zero_dev(request->length);
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE wrote %zu bytes", bytes);

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = etag_id;
	metadata.size = length;
	metadata.offset = offset;
	metadata.type = file_type;
	metadata.gzipped = request->gzip;
	fbr_strbcpy(metadata.path, url);

	// TODO url might have a prefix...

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

int
fbr_cstore_url_read(struct fbr_cstore_worker *worker, struct chttp_context *request)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(request);
	assert(request->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&request->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	const char *url = chttp_header_get_url(request);
	assert(url);
	size_t url_len = strlen(url);

	const char *host = chttp_header_get(request, "Host");
	assert(host);
	size_t host_len = strlen(host);

	fbr_id_t etag_match = 0;
	size_t if_match_len = 0;
	const char *if_match = chttp_header_get(request, "If-Match");
	if (if_match) {
		if_match_len = strlen(if_match);
		if (if_match_len >= 2 && if_match[if_match_len - 1] == '\"' &&
		    if_match[0] == '\"') {
			if_match++;
			if_match_len -= 2;
		}

		etag_match = fbr_id_parse(if_match, if_match_len);
		if (!etag_match) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR if-match");
			return 1;
		}
	}

	size_t offset;

	enum fbr_cstore_entry_type file_type = _parse_url(url, url_len, if_match, if_match_len,
		&offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url");
		return 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ %s %s %s %d",
		host, url, path, file_type);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_ok(cstore, hash);
	if (!entry) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR ok state");
		return 1;
	}

	assert_dev(entry->state == FBR_CSTORE_OK);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR open()");
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	struct stat st;
	int ret = fstat(fd, &st);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR stat()");
		fbr_cstore_remove(cstore, entry);
		assert_zero(close(fd));
		return 1;
	}

	size_t size = (size_t)st.st_size;

	struct fbr_cstore_metadata metadata;
	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	ret = fbr_cstore_metadata_read(path, &metadata);

	assert_zero_dev(ret);
	assert_dev(metadata.etag == etag_match); // TODO doesnt work for root
	assert_dev(metadata.offset == offset);
	assert_dev(metadata.size == size);
	assert_dev(metadata.type == file_type);

	if (ret || metadata.size != size || metadata.offset != offset ||
	    metadata.etag != etag_match) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR metadata()");
		fbr_cstore_remove(cstore, entry);
		assert_zero(close(fd));
		return 1;
	}

	char buffer[1024];
	size_t header_len = fbr_bprintf(buffer,
		"HTTP/1.1 200 OK\r\n"
		"Server: fiberfs cstore %s\r\n"
		"Content-Length: %zu\r\n\r\n", FIBERFS_VERSION, size);

	chttp_tcp_send(&request->addr, buffer, header_len);
	chttp_tcp_error_check(request);

	if (request->error) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR send() headers");
		fbr_cstore_release(cstore, entry);
		assert_zero(close(fd));
		return -1;
	}

	size_t bytes = 0;
	off_t off = 0;
	while (bytes < size) {
		ssize_t ret = sendfile(request->addr.sock, fd, &off, size - bytes);
		if (ret <= 0) {
			break;
		}

		bytes += ret;
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ read %zu bytes (sendfile)", bytes);

	if (bytes != size) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR sendfile()");
		fbr_cstore_release(cstore, entry);
		assert_zero(close(fd));
		chttp_error(request, CHTTP_ERR_NETWORK);
		return -1;
	}

	assert_zero(close(fd));
	fbr_cstore_release(cstore, entry);

	return 0;
}

int
fbr_cstore_url_delete(struct fbr_cstore_worker *worker, struct chttp_context *request)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(request);
	assert(request->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&request->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	const char *url = chttp_header_get_url(request);
	assert(url);
	size_t url_len = strlen(url);

	const char *host = chttp_header_get(request, "Host");
	assert(host);
	size_t host_len = strlen(host);

	fbr_id_t etag_match = 0;
	size_t if_match_len = 0;
	const char *if_match = chttp_header_get(request, "If-Match");
	if (if_match) {
		if_match_len = strlen(if_match);
		if (if_match_len >= 2 && if_match[if_match_len - 1] == '\"' &&
		    if_match[0] == '\"') {
			if_match++;
			if_match_len -= 2;
		}

		etag_match = fbr_id_parse(if_match, if_match_len);
	}
	if (!etag_match) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR if-match");
		return -1;
	}

	size_t offset;

	enum fbr_cstore_entry_type file_type = _parse_url(url, url_len, if_match, if_match_len,
		&offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url");
		return -1;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE %s %s %s %d", host, url, path,
		file_type);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR ok state");
		return 1;
	}

	fbr_cstore_entry_ok(entry);
	fbr_cstore_remove(cstore, entry);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE success");

	return 0;
}
