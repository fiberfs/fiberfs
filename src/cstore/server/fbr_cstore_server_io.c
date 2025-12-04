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

struct _cstore_entry_pair {
	struct fbr_cstore		*cstore;
	struct fbr_cstore_entry		*entry;
};

enum fbr_cstore_entry_type
fbr_cstore_url_parse(const char *url, size_t url_len, const char *etag, size_t etag_len,
    size_t *offset)
{
	assert(url && url_len);
	assert_dev(offset);

	*offset = 0;

	if (url_len <= sizeof(FBR_FIBERFS_NAME) || url[0] != '/') {
		return FBR_CSTORE_FILE_NONE;
	}

	for (size_t i = 0; i < url_len; i++) {
		if (url[i] == '?') {
			return FBR_CSTORE_FILE_NONE;
		} else if (i && url[i - 1] == '/' && url[i] == '.') {
			if (!strcmp(&url[i], FBR_FIBERFS_ROOT_NAME)) {
				assert_dev(i + 12 == url_len);
				return FBR_CSTORE_FILE_ROOT;
			} else if (!strncmp(&url[i], FBR_FIBERFS_INDEX_NAME ".",
			    sizeof(FBR_FIBERFS_INDEX_NAME))) {
				i += 14;
				if (i >= url_len || !etag_len) {
					return FBR_CSTORE_FILE_NONE;
				} else if (i + etag_len != url_len) {
					return FBR_CSTORE_FILE_NONE;
				}

				if (!strncmp(&url[i], etag, etag_len)) {
					assert_dev(i + etag_len == url_len);
					return FBR_CSTORE_FILE_INDEX;
				}

				return FBR_CSTORE_FILE_NONE;
			} else if (!strncmp(&url[i], FBR_FIBERFS_NAME,
			    sizeof(FBR_FIBERFS_NAME) - 1)) {
				return FBR_CSTORE_FILE_NONE;
			}
		} else if (url[i] == '.') {
			if (!etag_len) {
				continue;
			} else if (i + etag_len + 2 >= url_len) {
				return FBR_CSTORE_FILE_NONE;
			}

			if (!strncmp(&url[i + 1], etag, etag_len)) {
				i += 2 + etag_len;
				assert_dev(i < url_len);

				if (url[i - 1] != '.') {
					continue;
				}

				size_t end = i;
				while (url[end] >= '0' && url[end] <= '9') {
					end++;
				}

				if (url[end] != '.' || end == i || end == url_len) {
					continue;
				} else if (strcmp(&url[end], FBR_FIBERFS_CHUNK_NAME)) {
					continue;
				}

				*offset = fbr_parse_ulong(&url[i], end - i);
				if (!*offset) {
					if (url[i] != '0' || end - i != 1) {
						continue;
					}
				}

				return FBR_CSTORE_FILE_CHUNK;
			}
		}
	}

	return FBR_CSTORE_FILE_NONE;
}

static void
_cstore_entry_sendfile(struct chttp_context *http, void *arg)
{
	chttp_context_ok(http);
	assert(arg);

	struct _cstore_entry_pair *pair = arg;

	struct fbr_cstore *cstore = pair->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_entry *entry = pair->entry;
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_OK);
	assert(entry->bytes == (size_t)http->length);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, entry->hash, 0, &hashpath);

	int fd = open(hashpath.value, O_RDONLY);
	if (fd < 0) {
		chttp_error(http, CHTTP_ERR_NETWORK);
		return;
	}

	size_t bytes = fbr_cstore_s3_splice_out(cstore, &http->addr, fd, entry->bytes);

	assert_zero(close(fd));

	if (bytes != entry->bytes) {
		fbr_rlog(FBR_LOG_CS_S3, "URL_WRITE ERROR splice_out");
		chttp_error(http, CHTTP_ERR_NETWORK);
		return;
	}

	http->length -= bytes;
	assert_zero(http->length);
}

void
_cstore_root_proxy(struct fbr_cstore *cstore, struct chttp_context *http, const char *url,
    fbr_id_t etag_id, fbr_id_t etag_match)
{
	assert_dev(cstore);
	assert_dev(http);
	assert_dev(url);
	assert_dev(etag_id);

	char root_buffer[FBR_ROOT_JSON_SIZE];
	size_t bytes = 0;

	while (bytes < sizeof(root_buffer)) {
		bytes += chttp_body_read(http, root_buffer + bytes, sizeof(root_buffer) - bytes);
		assert_dev(bytes <= sizeof(root_buffer));

		if (http->error || http->state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (http->error || bytes == sizeof(root_buffer) || http->state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_WORKER, "ERROR S3 root_body");
		chttp_context_free(http);
		return;
	}

	struct fbr_writer *root_json = fbr_writer_alloc_dynamic(NULL, FBR_ROOT_JSON_SIZE);
	fbr_writer_add(NULL, root_json, root_buffer, bytes);
	fbr_writer_flush(NULL, root_json);
	assert_zero_dev(root_json->error);

	struct fbr_cstore_path root_path;
	fbr_cstore_path_url(cstore, url, &root_path);

	int error = fbr_cstore_s3_root_put(cstore, root_json, &root_path, etag_id, etag_match);
	if (error) {
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	fbr_cstore_http_respond(cstore, http, 200, "OK");
}

void
fbr_cstore_url_write(struct fbr_cstore_worker *worker, struct chttp_context *http)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_BODY);
	assert_zero(http->chunked);
	chttp_addr_connected(&http->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	if (http->chunked) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR chunked");
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	size_t offset;
	size_t length = http->length;
	assert(length);

	const char *url_encoded = chttp_header_get_url(http);
	assert(url_encoded);
	size_t url_encoded_len = strlen(url_encoded);
	if (url_encoded_len >= FBR_URL_MAX) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url_encoded_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_urldecode(url_encoded, url_encoded_len, url, sizeof(url));
	if (!url_len) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}
	assert(url[0] == '/');

	int ret = fbr_cstore_s3_validate(cstore, http);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR auth");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	const char *host = chttp_header_get(http, "Host");
	if (!host) {
		host = "";
	}
	size_t host_len = strlen(host);

	const char *etag = chttp_header_get(http, "ETag");
	if (!etag) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR no etag");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	size_t etag_len = strlen(etag);
	if (etag_len >= 2 && etag[etag_len - 1] == '\"' && etag[0] == '\"') {
		etag++;
		etag_len -= 2;
	}

	fbr_id_t etag_id = fbr_id_parse(etag, etag_len);
	if (!etag_id) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR etag");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	int unique = 0;
	const char *if_none_match = chttp_header_get(http, "If-None-Match");
	if (if_none_match) {
		if (!strcmp(if_none_match, "*")) {
			unique = 1;
		} else {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR if-none-match");
			fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
			return;
		}
	}

	fbr_id_t etag_match = 0;
	const char *if_match = chttp_header_get(http, "If-Match");
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
			fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
			return;
		}
	}

	enum fbr_cstore_entry_type file_type = fbr_cstore_url_parse(url, url_len, etag, etag_len,
		&offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	switch (file_type) {
		case FBR_CSTORE_FILE_CHUNK:
		case FBR_CSTORE_FILE_INDEX:
			if (!unique || etag_match) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_WRITE ERROR need unique");
				fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
				return;
			}
			break;
		case FBR_CSTORE_FILE_ROOT:
			if (!unique && !etag_match) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
					"URL_WRITE ERROR root missing conditions");
				fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
				return;
			}
			break;
		default:
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR url type");
			fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
			return;
	}

	// root files put first then write
	if (fbr_cstore_backend_enabled(cstore) && file_type == FBR_CSTORE_FILE_ROOT) {
		_cstore_root_proxy(cstore, http, url_encoded, etag_id, etag_match);
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE %s %s unique: %d match: %lu",
		fbr_cstore_type_name(file_type), hashpath.value, unique, etag_match);

	struct fbr_cstore_entry *entry = NULL;
	if (unique) {
		entry = fbr_cstore_io_get_loading(cstore, hash, length, &hashpath, 1);
		if (!entry) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR loading state");
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
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
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
		}
	}

	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	if (etag_match) {
		struct fbr_cstore_metadata metadata;
		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		int ret = fbr_cstore_metadata_read(&hashpath, &metadata);
		if (ret) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR metadata");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, entry);
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
		}

		if (metadata.etag != etag_match) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER,
				"URL_WRITE ERROR bad version want: %lu got: %lu",
				etag_match, metadata.etag);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, entry);
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
		}

		fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE conditions passed");

	int fd = open(hashpath.value, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	size_t bytes = fbr_cstore_s3_splice_in(cstore, http, fd, length);

	assert_zero(close(fd));

	if (bytes != length) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR splice_in (%zu)",
			bytes);

		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);

		if (!http->error) {
			chttp_error(http, CHTTP_ERR_NETWORK);
		}
		assert_dev(http->addr.state != CHTTP_ADDR_CONNECTED);

		return;
	} else {
		assert_dev(http->state >= CHTTP_STATE_IDLE);
		assert_zero_dev(http->length);
	}

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE wrote %zu bytes", bytes);

	struct fbr_cstore_path file_path;
	fbr_cstore_path_url(cstore, url_encoded, &file_path);

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = etag_id;
	metadata.size = length;
	metadata.offset = offset;
	metadata.type = file_type;
	metadata.gzipped = http->gzip;
	fbr_strbcpy(metadata.path, file_path.value);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_WRITE ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_http_respond(cstore, http, 500, "Error");
		return;
	}

	fbr_cstore_set_ok(entry);

	if (fbr_cstore_backend_enabled(cstore)) {
		assert(file_type != FBR_CSTORE_FILE_ROOT);

		struct chttp_context http_backend;
		chttp_context_init(&http_backend);

		struct _cstore_entry_pair pair;
		pair.cstore = cstore;
		pair.entry = entry;

		fbr_s3_send_put(cstore, &http_backend, file_type, &file_path, length, etag_id, 0,
			metadata.gzipped, _cstore_entry_sendfile, &pair);

		if (http_backend.error || http_backend.status != 200) {
			fbr_cstore_release(cstore, entry);
			chttp_context_free(&http_backend);
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
		}

		// TODO return the http_backend response

		chttp_context_free(&http_backend);
	}

	fbr_cstore_release(cstore, entry);

	fbr_cstore_http_respond(cstore, http, 200, "OK");
}

void
fbr_cstore_url_read(struct fbr_cstore_worker *worker, struct chttp_context *http)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&http->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	const char *url_encoded = chttp_header_get_url(http);
	assert(url_encoded);
	size_t url_encoded_len = strlen(url_encoded);
	if (url_encoded_len >= FBR_URL_MAX) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url_encoded_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_urldecode(url_encoded, url_encoded_len, url, sizeof(url));
	if (!url_len) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}
	assert(url[0] == '/');

	int ret = fbr_cstore_s3_validate(cstore, http);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR auth");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	const char *host = chttp_header_get(http, "Host");
	assert(host);
	size_t host_len = strlen(host);

	fbr_id_t etag_match = 0;
	size_t if_match_len = 0;
	const char *if_match = chttp_header_get(http, "If-Match");
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
			fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
			return;
		}
	}

	size_t offset;

	enum fbr_cstore_entry_type file_type = fbr_cstore_url_parse(url, url_len, if_match,
		if_match_len, &offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR url");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);
	struct fbr_cstore_metadata metadata;
	struct fbr_cstore_entry *entry;
	int fd;
	size_t size;
	int retry = 0;

	while (1) {
		struct fbr_cstore_hashpath hashpath;
		fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ %s %s (retry: %d)",
			fbr_cstore_type_name(file_type), hashpath.value, retry);

		if (retry == 1) {
			if (!fbr_cstore_backend_enabled(cstore)) {
				fbr_cstore_http_respond(cstore, http, 500, "Error");
				return;
			}

			struct fbr_cstore_path file_path;
			fbr_cstore_path_url(cstore, url_encoded, &file_path);

			// Its possible someone else fetched this, ignore the error...
			(void)fbr_cstore_s3_get_write(cstore, hash, &file_path, etag_match, 0,
				file_type);
		} else if (retry > 1) {
			fbr_cstore_http_respond(cstore, http, 500, "Error");
			return;
		}

		retry++;

		entry = fbr_cstore_io_get_ok(cstore, hash);
		if (!entry) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR ok state");
			continue;
		}

		assert_dev(entry->state == FBR_CSTORE_OK);

		fd = open(hashpath.value, O_RDONLY);
		if (fd < 0) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR open()");
			fbr_cstore_remove(cstore, entry);
			continue;
		}

		struct stat st;
		int ret = fstat(fd, &st);
		if (ret) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR stat()");
			fbr_cstore_remove(cstore, entry);
			assert_zero(close(fd));
			continue;
		}

		size = (size_t)st.st_size;

		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		ret = fbr_cstore_metadata_read(&hashpath, &metadata);

		// root requests dont If-Match
		if (file_type == FBR_CSTORE_FILE_ROOT && !etag_match) {
			etag_match = metadata.etag;
		}

		if (ret || metadata.size != size || metadata.offset != offset ||
		    metadata.etag != etag_match || metadata.type != file_type) {
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR metadata()");
			fbr_cstore_remove(cstore, entry);
			assert_zero(close(fd));
			continue;
		}

		break;
	}

	// TODO do we care about accept-encoding gzip?

	char etag[FBR_ID_STRING_MAX];
	fbr_id_string(metadata.etag, etag, sizeof(etag));

	char fiber_id[32];
	fbr_cstore_request_id(fiber_id, sizeof(fiber_id));

	char buffer[1024];
	size_t header_len = fbr_bprintf(buffer,
		"HTTP/1.1 200 OK\r\n"
		"Server: fiberfs cstore %s\r\n"
		"%s"
		"%s"
		"ETag: \"%s\"\r\n"
		"FiberFS-ID: %s\r\n"
		"Content-Length: %zu\r\n\r\n",
			FIBERFS_VERSION,
			metadata.gzipped ? "Content-Encoding: gzip\r\n" : "",
			cstore->epool.timeout_sec ? "" : "Connection: close\r\n",
			etag, fiber_id, size);

	chttp_tcp_send(&http->addr, buffer, header_len);
	chttp_tcp_error_check(http);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "sent response 200 OK");

	if (http->error) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR send() headers");
		fbr_cstore_release(cstore, entry);
		assert_zero(close(fd));
		return;
	}

	size_t bytes = fbr_cstore_s3_splice_out(cstore, &http->addr, fd, size);

	assert_zero(close(fd));

	if (bytes != size) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_READ ERROR splice_out");
		fbr_cstore_release(cstore, entry);
		chttp_error(http, CHTTP_ERR_NETWORK);
		return;
	}

	fbr_cstore_release(cstore, entry);
}

void
fbr_cstore_url_delete(struct fbr_cstore_worker *worker, struct chttp_context *http)
{
	fbr_cstore_worker_ok(worker);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&http->addr);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	const char *url_encoded = chttp_header_get_url(http);
	assert(url_encoded);
	size_t url_encoded_len = strlen(url_encoded);
	if (url_encoded_len >= FBR_URL_MAX) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url_encoded_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_urldecode(url_encoded, url_encoded_len, url, sizeof(url));
	if (!url_len) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url_len");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}
	assert(url[0] == '/');

	int ret = fbr_cstore_s3_validate(cstore, http);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR auth");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	const char *host = chttp_header_get(http, "Host");
	assert(host);
	size_t host_len = strlen(host);

	fbr_id_t etag_match = 0;
	size_t if_match_len = 0;
	const char *if_match = chttp_header_get(http, "If-Match");
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
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	size_t offset;

	enum fbr_cstore_entry_type file_type = fbr_cstore_url_parse(url, url_len, if_match,
		if_match_len, &offset);
	if (file_type == FBR_CSTORE_FILE_NONE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR url");
		fbr_cstore_http_respond(cstore, http, 400, "Bad Request");
		return;
	}

	int backend = fbr_cstore_backend_enabled(cstore);

	if (!cstore->delete_cache && backend) {
		struct fbr_cstore_url url_enc;
		fbr_cstore_s3_url_init(&url_enc, url_encoded, url_encoded_len);

		int error = fbr_cstore_s3_send_delete(cstore, &url_enc, etag_match);
		if (error) {
			fbr_cstore_http_respond(cstore, http, 500, "Error");
		} else {
			fbr_cstore_http_respond(cstore, http, 200, "OK");
		}
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_url(host, host_len, url, url_len);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE %s",
		fbr_cstore_type_name(file_type));

	int error = 0;

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (entry) {
		fbr_cstore_entry_ok(entry);

		if (!backend) {
			struct fbr_cstore_hashpath hashpath;
			fbr_cstore_hashpath(cstore, hash, 1, &hashpath);

			struct fbr_cstore_metadata metadata;
			int ret = fbr_cstore_metadata_read(&hashpath, &metadata);
			if (ret || metadata.etag != etag_match) {
				fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR etag");
				fbr_cstore_release(cstore, entry);
				fbr_cstore_http_respond(cstore, http, 500, "Error");
				return;
			}
		}

		fbr_cstore_remove(cstore, entry);

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE success");
	} else {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "URL_DELETE ERROR ok state");
		error = 1;
	}

	if (backend) {
		struct fbr_cstore_url url_enc;
		fbr_cstore_s3_url_init(&url_enc, url_encoded, url_encoded_len);

		error = fbr_cstore_s3_send_delete(cstore, &url_enc, etag_match);
	}

	if (error) {
		fbr_cstore_http_respond(cstore, http, 500, "Error");
	} else {
		fbr_cstore_http_respond(cstore, http, 200, "OK");
	}
}
