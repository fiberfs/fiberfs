/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "utils/fbr_sys.h"

static fbr_hash_t
_s3_request_url(struct fbr_cstore *cstore, const char *method, const char *url, size_t url_len,
    struct chttp_context *http, int retries)
{
	assert_dev(cstore);
	assert_dev(cstore->s3.backend);
	assert_dev(method);
	assert_dev(url);
	assert_dev(http);

	chttp_set_method(http, method);
	chttp_set_url(http, url);

	struct fbr_cstore_backend *s3_backend = cstore->s3.backend;
	chttp_header_add(http, "Host", s3_backend->host);

	fbr_rlog(FBR_LOG_CS_S3, "S3 %s %s (retry: %d)", method, url, retries);

	if (!strcmp(method, "GET")) {
		chttp_header_add(http, "Accept-Encoding", "gzip");
	}

	char buffer[32];
	fbr_strbcpy(buffer, "0");
	struct fbr_request *request = fbr_request_get();
	if (request) {
		fbr_bprintf(buffer, "%lu", request->id);
	} else {
		struct fbr_cstore_worker *worker = fbr_cstore_worker_get();
		if (worker) {
			fbr_bprintf(buffer, "%lu", worker->request_id);
		}
	}
	chttp_header_add(http, "FiberFS-ID", buffer);

	fbr_hash_t hash = fbr_cstore_hash_url(s3_backend->host, s3_backend->host_len, url,
		url_len);
	return hash;
}

static fbr_hash_t
_s3_request_path(struct fbr_cstore *cstore, const char *method, const char *path,
    struct chttp_context *http, int retries)
{
	assert_dev(path);

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_cstore_s3_url(cstore, path, url, sizeof(url));

	return _s3_request_url(cstore, method, url, url_len, http, retries);
}

size_t
fbr_cstore_s3_splice(struct fbr_cstore *cstore, struct chttp_context *http, int fd, size_t size)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_BODY);
	assert(fd >= 0);

	size_t bytes = 0;
	int fallback_rw = 0;
	if (cstore->cant_splice || http->chunked || !size) {
		fallback_rw = 1;
	}

	while (!fallback_rw && bytes < size) {
		assert(size == (size_t)http->length);
		ssize_t ret = splice(http->addr.sock, NULL, fd, NULL, size - bytes, SPLICE_F_MOVE);
		if (ret <= 0) {
			if (bytes == 0 && errno == EINVAL) {
				fbr_rlog(FBR_LOG_CS_S3, "Cannot splice, falling back");
				cstore->cant_splice = 1;
				fallback_rw = 1;
			} else {
				chttp_error(http, CHTTP_ERR_RESP_BODY);
			}
			break;
		}

		bytes += (size_t)ret;
	}

	while (fallback_rw && (!size || bytes < size)) {
		// TODO needs to be bigger
		char buffer[4096];
		size_t ret = chttp_body_read(http, buffer, sizeof(buffer));
		if (http->error) {
			break;
		} else if (ret == 0) {
			break;
		}

		ret = fbr_sys_write(fd, buffer, ret);
		if (ret == 0) {
			chttp_error(http, CHTTP_ERR_RESP_BODY);
			break;
		}

		bytes += (size_t)ret;
	}

	if (!fallback_rw && !http->error) {
		http->length = 0;
		http->state = CHTTP_STATE_IDLE;
	}

	fbr_rlog(FBR_LOG_CS_S3, "wrote %zu bytes (%s) error: %d", bytes,
		fallback_rw ? "read/write" : "splice", http->error);

	return bytes;
}

void
fbr_cstore_s3_send_get(struct fbr_cstore *cstore, struct chttp_context *http,
    const char *file_path, fbr_id_t id, int retries)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);
	assert(http->state == CHTTP_STATE_NONE);
	assert_zero(http->error);
	assert(file_path);

	fbr_hash_t hash = _s3_request_path(cstore, "GET", file_path, http, retries);

	if (id) {
		char buffer[32];
		fbr_cstore_etag(id, buffer, sizeof(buffer));
		chttp_header_add(http, "If-Match", buffer);
	}

	struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, retries);
	fbr_cstore_backend_ok(backend);

	chttp_connect(http, backend->host, backend->host_len, backend->port, backend->tls);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(http),
			http->error);
		return;
	}

	chttp_send(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(http),
			http->error);
		return;
	}

	chttp_receive(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(http),
			http->error);
		return;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 response: %d", http->status);
	fbr_cstore_http_log(http);
}

static int
_s3_send_put(struct fbr_cstore *cstore, struct chttp_context *http,
    enum fbr_cstore_entry_type type, const char *path, size_t length, fbr_id_t etag,
    fbr_id_t existing, fbr_cstore_s3_put_f data_cb, void *put_arg, int retry)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);
	assert_dev(http->state == CHTTP_STATE_NONE);
	assert_dev(path);
	assert_dev(length);
	assert_dev(etag);
	assert_dev(data_cb);

	if (!fbr_cstore_backend_enabled(cstore)) {
		return 0;
	}

	// TODO
	http->addr.timeout_connect_ms = 3000;
	http->addr.timeout_transfer_ms = 5000;

	if (retry) {
		http->new_conn = 1;
	}

	fbr_hash_t hash = _s3_request_path(cstore, "PUT", path, http, retry);

	char buffer[32];
	fbr_bprintf(buffer, "%zu", length);

	chttp_header_add(http, "Content-Length", buffer);

	if (existing) {
		fbr_cstore_etag(existing, buffer, sizeof(buffer));
		chttp_header_add(http, "If-Match", buffer);
	} else {
		chttp_header_add(http, "If-None-Match", "*");
	}

	fbr_cstore_etag(etag, buffer, sizeof(buffer));
	chttp_header_add(http, "ETag", buffer);

	switch (type) {
		case FBR_CSTORE_FILE_INDEX:
			chttp_header_add(http, "Content-Encoding", "gzip");
			chttp_header_add(http, "Content-Type", "application/json");
			break;
		case FBR_CSTORE_FILE_ROOT:
			chttp_header_add(http, "Content-Type", "application/json");
			// TODO do we want to force a max-age?
			//chttp_header_add(http, "Cache-Control", "max-age=86400");
			break;
		default:
			chttp_header_add(http, "Content-Type", "application/octet-stream");
			break;
	}

	struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, retry);
	chttp_connect(http, backend->host, backend->host_len, backend->port, backend->tls);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp connection %s", backend->host);
		return 1;
	}

	chttp_send(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp send");
		// Retry
		if (http->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}

	data_cb(http, put_arg);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp body");
		// Retry
		if (http->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}
	assert_zero_dev(http->length);

	chttp_receive(http);
	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp receive");
		// Retry
		if (http->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}

	fbr_cstore_http_log(http);

	size_t body_len;
	do {
		char buffer[4096];
		body_len = chttp_body_read(http, buffer, sizeof(buffer));
	} while (body_len);

	if (http->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp rbody");
		return 1;
	}

	return 0;
}

int
fbr_cstore_s3_send_finish(struct fbr_cstore *cstore, struct fbr_cstore_op_sync *sync,
    struct chttp_context *http, int error)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);

	if (sync) {
		fbr_cstore_op_sync_wait(sync);
		if (sync->error) {
			assert_dev(http->state == CHTTP_STATE_NONE);
			error = 1;
		}

		fbr_cstore_op_sync_free(sync);
	}

	if (http->state == CHTTP_STATE_NONE) {
		chttp_context_free(http);
		return error;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 response: %d (%d %d %s)", http->status, http->state,
		http->error, chttp_error_msg(http));

	if (http->error || http->status != 200) {
		error = 1;
	} else {
		error = 0;
	}

	chttp_context_free(http);

	return error;
}

int
fbr_cstore_s3_get(struct fbr_cstore *cstore, fbr_hash_t hash, const char *file_path, fbr_id_t id,
    size_t size, enum fbr_cstore_entry_type type)
{
	fbr_cstore_ok(cstore);
	assert(file_path);
	assert(id);
	assert(type > FBR_CSTORE_FILE_NONE && type <= FBR_CSTORE_FILE_ROOT);

	if (!fbr_cstore_backend_enabled(cstore)) {
		return 1;
	}

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rlog(FBR_LOG_CS_S3, "S3_GET %s", file_path);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, size, path, 1);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET loading state");
		return 1;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int retries = 0;
	struct chttp_context http;

	while (retries <= 1) {
		chttp_context_init(&http);

		if (retries) {
			http.new_conn = 1;
		}
		retries++;

		fbr_cstore_s3_send_get(cstore, &http, file_path, id, retries);
		if (http.error) {
			continue;
		}

		break;
	}

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET: %d %d", http.error, http.status);
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);

		int error = http.status ? http.status : 1;
		assert_dev(error > 0);
		chttp_context_free(&http);

		return error;
	} else if (!http.chunked && size && (size_t)http.length != size) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET length");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&http);
		return 1;
	}

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&http);
		return 1;
	}

	size_t bytes = fbr_cstore_s3_splice(cstore, &http, fd, size);

	assert_zero(close(fd));

	if (http.error || (size && bytes != size)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&http);
		return 1;
	} else {
		assert_dev(http.state >= CHTTP_STATE_IDLE);
		assert_zero_dev(http.length);
	}

	if (!size) {
		assert_zero_dev(entry->bytes);
		size = bytes;

		int ret = fbr_cstore_set_size(cstore, entry, bytes);
		if (ret) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET size");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, entry);
			chttp_context_free(&http);
			return 1;
		}
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = id;
	metadata.size = size;
	metadata.type = type;
	metadata.gzipped = http.gzip;
	fbr_strbcpy(metadata.path, file_path);

	chttp_context_free(&http);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3_GET done %zu bytes", bytes);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	return 0;
}

void
fbr_cstore_s3_send_delete(struct fbr_cstore *cstore, const char *s3_url, fbr_id_t id)
{
	fbr_cstore_ok(cstore);
	assert(s3_url);

	if (!fbr_cstore_backend_enabled(cstore)) {
		return;
	}

	size_t s3_url_len = strlen(s3_url);

	int retries = 0;
	struct chttp_context http;
	chttp_context_init(&http);

	while (retries <= 1) {
		if (retries) {
			chttp_context_reset(&http);
			http.new_conn = 1;
		}
		retries++;

		fbr_hash_t hash = _s3_request_url(cstore, "DELETE", s3_url, s3_url_len, &http,
			retries);

		char buffer[32];
		fbr_cstore_etag(id, buffer, sizeof(buffer));
		chttp_header_add(&http, "If-Match", buffer);

		struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, retries);
		fbr_cstore_backend_ok(backend);

		chttp_connect(&http, backend->host, backend->host_len, backend->port,
			backend->tls);
		if (http.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp connection %s", backend->host);
			chttp_context_free(&http);
			return;
		}

		chttp_send(&http);
		if (http.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp send: %s", chttp_error_msg(&http));
			if (http.addr.reused) {
				continue;
			}
			chttp_context_free(&http);
			return;
		}

		chttp_receive(&http);
		if (http.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp recv: %s", chttp_error_msg(&http));
			if (http.addr.reused) {
				continue;
			}
			chttp_context_free(&http);
			return;
		}

		fbr_cstore_http_log(&http);

		break;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 DELETE %d %d", http.error, http.status);

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp: %d %d", http.error, http.status);
		chttp_context_free(&http);
		return;
	}

	chttp_context_free(&http);
}

static void
_s3_wbuffer_data_cb(struct chttp_context *http, void *arg)
{
	chttp_context_ok(http);
	assert(arg);

	struct fbr_wbuffer *wbuffer = arg;
	fbr_wbuffer_ok(wbuffer);

	chttp_body_send(http, wbuffer->buffer, wbuffer->end);
	assert_zero(http->length);
}

void
fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *http,
    const char *path, struct fbr_wbuffer *wbuffer)
{
	int error = _s3_send_put(cstore, http, FBR_CSTORE_FILE_CHUNK, path, wbuffer->end,
		wbuffer->id, 0, _s3_wbuffer_data_cb, wbuffer, 0);
	if (error < 0) {
		chttp_context_reset(http);
		error = _s3_send_put(cstore, http, FBR_CSTORE_FILE_CHUNK, path, wbuffer->end,
			wbuffer->id, 0, _s3_wbuffer_data_cb, wbuffer, 1);
		assert_dev(error >= 0);
	}
}

void
fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct fbr_cstore_op_sync *sync, struct chttp_context *http, struct fbr_wbuffer *wbuffer,
    int error)
{
	fbr_fs_ok(fs);
	fbr_wbuffer_ok(wbuffer);

	error = fbr_cstore_s3_send_finish(cstore, sync, http, error);
	if (error) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
	}
}

static inline void
_s3_chunk_read_error(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_cstore_entry *entry,
    struct fbr_file *file, struct fbr_chunk *chunk, struct chttp_context *http)
{
	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);

	fbr_cstore_set_error(entry);
	fbr_cstore_release(cstore, entry);

	chttp_context_free(http);
}

static inline void
_s3_chunk_readwrite_error(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct fbr_cstore_entry *entry, struct fbr_file *file, struct fbr_chunk *chunk, int async)
{
	if (async) {
		fbr_file_LOCK(fs, file);
		fbr_chunk_release(chunk);
		fbr_file_UNLOCK(file);
		fbr_inode_release(fs, &file);
	}

	fbr_cstore_set_error(entry);
	fbr_cstore_remove(cstore, entry);
}

void
fbr_cstore_s3_chunk_read(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_file *file,
    struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_cstore_ok(cstore);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY || chunk->state == FBR_CHUNK_LOADING);
	assert_zero(chunk->external);

	if (!fbr_cstore_backend_enabled(cstore)) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	int async = 0;
	if (chunk->state == FBR_CHUNK_LOADING) {
		async = 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, chunk->id, chunk->offset);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, chunk->length,
		NULL, 1);
	if (!entry) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_rlog(FBR_LOG_CS_S3, "ERROR s3 loading state");
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	char path[FBR_PATH_MAX];
	fbr_cstore_path_chunk(NULL, file, chunk->id, chunk->offset, 0, path, sizeof(path));

	int retries = 0;
	struct chttp_context http;

	while (retries <= 1) {
		chttp_context_init(&http);

		if (retries) {
			http.new_conn = 1;
		}
		retries++;

		fbr_cstore_s3_send_get(cstore, &http, path, chunk->id, retries);
		if (http.error) {
			continue;
		}

		break;
	}

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp: %d %d", http.error, http.status);
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &http);
		return;
	} else if (!http.chunked && (size_t)http.length != chunk->length) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp length");
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &http);
		return;
	}

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	size_t bytes = 0;
	while (bytes < chunk->length) {
		bytes += chttp_body_read(&http, chunk->data + bytes, chunk->length - bytes);

		if (http.error || http.state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (http.error || bytes != chunk->length || http.state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp bytes");
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &http);
		return;
	}

	chttp_context_free(&http);

	// Write back the chunk to the cstore

	if (async) {
		fbr_file_ref_inode(fs, file);
		fbr_file_LOCK(fs, file);
		fbr_chunk_take(chunk);
		fbr_file_UNLOCK(file);
	}

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);

	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rlog(FBR_LOG_CS_S3, "READ S3 %zu bytes WRITE S3 chunk: %s", bytes, path);

	int ret = fbr_sys_mkdirs(path);
	if (ret || fbr_sys_exists(path)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite mkdir/exists (%d)", ret);
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite open()");
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	bytes = fbr_sys_write(fd, chunk->data, chunk->length);
	assert_zero(close(fd));

	if (bytes != chunk->length) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR rwrite bytes");
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = chunk->id;
	metadata.size = bytes;
	metadata.offset = chunk->offset;
	metadata.type = FBR_CSTORE_FILE_CHUNK;

	fbr_cstore_path_chunk(NULL, file, chunk->id, chunk->offset, 0, path, sizeof(path));
	fbr_strbcpy(metadata.path, path);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR write metadata");
		_s3_chunk_readwrite_error(fs, cstore, entry, file, chunk, async);
		return;
	}

	if (async) {
		fbr_file_LOCK(fs, file);
		fbr_chunk_release(chunk);
		fbr_file_UNLOCK(file);
		fbr_inode_release(fs, &file);
	}

	fbr_rlog(FBR_LOG_CS_S3, "READ WRITE S3 done %zu bytes", bytes);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);
}

static void
_s3_writer_data_cb(struct chttp_context *http, void *arg)
{
	chttp_context_ok(http);
	assert(arg);

	struct fbr_writer *writer = arg;
	fbr_writer_ok(writer);
	assert_dev(writer->bytes);
	assert_dev(writer->output);
	assert_zero(writer->error);

	struct fbr_buffer *output = writer->output;
	while (output) {
		fbr_buffer_ok(output);

		if (output->buffer_pos) {
			chttp_body_send(http, output->buffer, output->buffer_pos);
			if (http->error) {
				return;
			}
		}

		output = output->next;
	}

	assert_zero(http->length);
}

void
fbr_cstore_s3_index_send(struct fbr_cstore *cstore, struct chttp_context *http,
    const char *path, struct fbr_writer *writer, fbr_id_t id)
{
	int error = _s3_send_put(cstore, http, FBR_CSTORE_FILE_INDEX, path, writer->bytes, id, 0,
		_s3_writer_data_cb, writer, 0);
	if (error < 0) {
		chttp_context_reset(http);
		error = _s3_send_put(cstore, http, FBR_CSTORE_FILE_INDEX, path, writer->bytes, id,
			0, _s3_writer_data_cb, writer, 1);
		assert_dev(error >= 0);
	}
}

int
fbr_cstore_s3_root_write(struct fbr_cstore *cstore, struct fbr_writer *root_json,
    char *root_path, fbr_id_t version, fbr_id_t existing)
{
	fbr_cstore_ok(cstore);
	fbr_writer_ok(root_json);
	assert(root_json->bytes);
	assert(root_path);
	assert(version);
	assert(fbr_cstore_backend_enabled(cstore));

	struct chttp_context http;
	chttp_context_init(&http);

	int error = _s3_send_put(cstore, &http, FBR_CSTORE_FILE_ROOT, root_path, root_json->bytes,
		version, existing, _s3_writer_data_cb, root_json, 0);
	if (error < 0) {
		chttp_context_reset(&http);
		error =_s3_send_put(cstore, &http, FBR_CSTORE_FILE_ROOT, root_path,
			root_json->bytes, version, existing, _s3_writer_data_cb, root_json, 1);
		assert_dev(error >= 0);
	}

	error = fbr_cstore_s3_send_finish(cstore, NULL, &http, error);
	if (error) {
		return error;
	}

	fbr_cstore_async_root_write(cstore, root_json, root_path, version);

	return 0;
}

fbr_id_t
fbr_cstore_s3_root_read(struct fbr_fs *fs, struct fbr_cstore *cstore, char *root_path)
{
	fbr_cstore_ok(cstore);
	assert(root_path);

	int retries = 0;
	struct chttp_context http;

	while (retries <= 1) {
		chttp_context_init(&http);

		if (retries) {
			http.new_conn = 1;
		}
		retries++;

		fbr_cstore_s3_send_get(cstore, &http, root_path, 0, retries);
		if (http.error) {
			continue;
		}

		break;
	}

	if (http.error || http.status != 200) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR S3: %d %d", http.error, http.status);
		chttp_context_free(&http);
		return 0;
	}

	char root_json[FBR_ROOT_JSON_SIZE];
	size_t bytes = 0;

	while (bytes < sizeof(root_json)) {
		bytes += chttp_body_read(&http, root_json + bytes, sizeof(root_json) - bytes);
		assert_dev(bytes <= sizeof(root_json));

		if (http.error || http.state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (http.error || bytes == sizeof(root_json) || http.state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR S3 body");
		chttp_context_free(&http);
		return 0;
	}

	chttp_context_free(&http);

	fbr_id_t version = fbr_root_json_parse(root_json, bytes);
	if (!version) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR S3 json");
		return 0;
	}

	struct fbr_writer *json_writer = fbr_writer_alloc_dynamic(fs, FBR_ROOT_JSON_SIZE);
	fbr_writer_add(fs, json_writer, root_json, bytes);
	fbr_writer_flush(fs, json_writer);
	assert_zero(json_writer->error);

	fbr_cstore_async_root_write(cstore, json_writer, root_path, version);

	return version;
}
