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

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "utils/fbr_sys.h"

static fbr_hash_t
_s3_request_url(struct fbr_cstore *cstore, const char *path, struct chttp_context *request)
{
	assert_dev(cstore);
	assert_dev(cstore->s3.backend);
	assert_dev(path);
	assert_dev(request);

	char buffer[FBR_PATH_MAX];
	size_t buffer_len = fbr_cstore_s3_url(cstore, path, buffer, sizeof(buffer));
	chttp_set_url(request, buffer);

	struct fbr_cstore_backend *s3_backend = cstore->s3.backend;
	chttp_header_add(request, "Host", s3_backend->host);

	fbr_hash_t hash = fbr_cstore_hash_url(s3_backend->host, s3_backend->host_len, buffer,
		buffer_len);
	return hash;
}

size_t
fbr_cstore_s3_splice(struct fbr_cstore *cstore, struct chttp_context *request, int fd, size_t size)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(request);
	assert(request->state == CHTTP_STATE_BODY);
	assert(fd >= 0);
	assert(size);

	size_t bytes = 0;
	int fallback_rw = 0;
	if (cstore->cant_splice || request->chunked) {
		fallback_rw = 1;
	}

	while (!fallback_rw && bytes < size) {
		assert(size == (size_t)request->length);
		ssize_t ret = splice(request->addr.sock, NULL, fd, NULL, size, SPLICE_F_MOVE);
		if (ret < 0) {
			if (bytes == 0 && errno == EINVAL) {
				fbr_rlog(FBR_LOG_CS_S3, "Cannot splice, falling back");
				cstore->cant_splice = 1;
				fallback_rw = 1;
			}
			break;
		} else if (ret == 0) {
			break;
		}

		bytes += (size_t)ret;
	}

	while (fallback_rw && bytes < size) {
		// TODO needs to be bigger
		char buffer[4096];
		size_t ret = chttp_body_read(request, buffer, sizeof(buffer));
		if (request->error) {
			break;
		} else if (ret == 0) {
			break;
		}

		ret = fbr_sys_write(fd, buffer, ret);
		if (ret == 0) {
			break;
		}

		bytes += (size_t)ret;
	}

	if (!fallback_rw) {
		request->length = 0;
		request->state = CHTTP_STATE_IDLE;
	}

	fbr_rlog(FBR_LOG_CS_S3, "wrote %zu bytes (%s)", bytes,
		fallback_rw ? "read/write" : "splice");

	return bytes;
}

void
fbr_cstore_s3_send_get(struct fbr_cstore *cstore, struct chttp_context *request,
    const char *file_path, fbr_id_t id, int retries)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(request);
	assert(request->state == CHTTP_STATE_NONE);
	assert_zero(request->error);
	assert(file_path);

	chttp_set_method(request, "GET");
	fbr_hash_t hash = _s3_request_url(cstore, file_path, request);

	chttp_dpage_ok(request->dpage);
	int url_len = 4;
	while (request->dpage->data[url_len] > ' ') {
		url_len++;
	}
	fbr_rlog(FBR_LOG_CS_S3, "S3 %.*s", url_len, request->dpage->data);

	char buffer[32];
	fbr_cstore_etag(id, buffer, sizeof(buffer));
	chttp_header_add(request, "If-Match", buffer);

	struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, retries);
	fbr_cstore_backend_ok(backend);

	chttp_connect(request, backend->host, backend->host_len, backend->port, backend->tls);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(request),
			request->error);
		return;
	}

	chttp_send(request);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(request),
			request->error);
		return;
	}

	chttp_receive(request);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "S3 ERROR %s (%d)", chttp_error_msg(request),
			request->error);
		return;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 response: %d", request->status);
}

void
fbr_cstore_s3_send_delete(struct fbr_cstore *cstore, const char *s3_url, fbr_id_t id)
{
	fbr_cstore_ok(cstore);
	assert(s3_url);

	if (!fbr_cstore_backend_enabled(cstore)) {
		return;
	}
	struct fbr_cstore_backend *s3_backend = cstore->s3.backend;
	fbr_cstore_backend_ok(s3_backend);

	fbr_hash_t hash = fbr_cstore_hash_url(s3_backend->host, s3_backend->host_len, s3_url,
		strlen(s3_url));

	int retries = 0;
	struct chttp_context request;
	chttp_context_init(&request);

	while (retries <= 1) {
		struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, retries);
		fbr_cstore_backend_ok(backend);

		if (retries) {
			chttp_context_reset(&request);
			request.new_conn = 1;
		}
		retries++;

		chttp_set_method(&request, "DELETE");
		chttp_set_url(&request, s3_url);

		if (s3_backend) {
			chttp_header_add(&request, "Host", s3_backend->host);
		} else {
			chttp_header_add(&request, "Host", backend->host);
		}

		fbr_rlog(FBR_LOG_CS_S3, "S3 DELETE %s (%d)", s3_url, retries);

		char buffer[32];
		fbr_cstore_etag(id, buffer, sizeof(buffer));
		chttp_header_add(&request, "If-Match", buffer);

		chttp_connect(&request, backend->host, backend->host_len, backend->port,
			backend->tls);
		if (request.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp connection %s", backend->host);
			chttp_context_free(&request);
			return;
		}

		chttp_send(&request);
		if (request.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp send: %s", chttp_error_msg(&request));
			if (request.addr.reused) {
				continue;
			}
			chttp_context_free(&request);
			return;
		}

		chttp_receive(&request);
		if (request.error) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp recv: %s", chttp_error_msg(&request));
			if (request.addr.reused) {
				continue;
			}
			chttp_context_free(&request);
			return;
		}

		break;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 DELETE %d %d", request.error, request.status);

	if (request.error || request.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp: %d %d", request.error, request.status);
		chttp_context_free(&request);
		return;
	}

	chttp_context_free(&request);
}

static int
_s3_send_put(struct fbr_cstore *cstore, struct chttp_context *request,
    const char *path, size_t length, fbr_id_t etag, fbr_id_t existing, fbr_cstore_s3_put_f data_cb,
    void *put_arg, int retry)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(request);
	assert_dev(request->state == CHTTP_STATE_NONE);
	assert_dev(path);
	assert_dev(length);
	assert_dev(etag);
	assert_dev(data_cb);

	if (!fbr_cstore_backend_enabled(cstore)) {
		return 0;
	}

	// TODO
	request->addr.timeout_connect_ms = 3000;
	request->addr.timeout_transfer_ms = 5000;

	if (retry) {
		request->new_conn = 1;
	}

	chttp_set_method(request, "PUT");
	fbr_hash_t hash = _s3_request_url(cstore, path, request);

	chttp_dpage_ok(request->dpage);
	int url_len = 4;
	while (request->dpage->data[url_len] > ' ') {
		url_len++;
	}
	fbr_rlog(FBR_LOG_CS_S3, "S3 %.*s (retry: %d)", url_len, request->dpage->data, retry);

	char buffer[32];
	fbr_bprintf(buffer, "%zu", length);

	chttp_header_add(request, "Content-Length", buffer);

	if (existing) {
		fbr_cstore_etag(existing, buffer, sizeof(buffer));
		chttp_header_add(request, "If-Match", buffer);
	} else {
		chttp_header_add(request, "If-None-Match", "*");
	}

	fbr_cstore_etag(etag, buffer, sizeof(buffer));
	chttp_header_add(request, "ETag", buffer);

	struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash, retry);
	chttp_connect(request, backend->host, backend->host_len, backend->port, backend->tls);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp connection %s", backend->host);
		return 1;
	}

	chttp_send(request);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp send");
		// Retry
		if (request->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}

	data_cb(request, put_arg);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp body");
		// Retry
		if (request->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}
	assert_zero_dev(request->length);

	chttp_receive(request);
	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp receive");
		// Retry
		if (request->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}

	size_t body_len;
	do {
		char buffer[4096];
		body_len = chttp_body_read(request, buffer, sizeof(buffer));
	} while (body_len);

	if (request->error) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp rbody");
		return 1;
	}

	return 0;
}

int
fbr_cstore_s3_send_finish(struct fbr_cstore *cstore, struct fbr_cstore_op_sync *sync,
    struct chttp_context *request, int error)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(request);

	if (sync) {
		fbr_cstore_op_sync_wait(sync);
		if (sync->error) {
			assert_dev(request->state == CHTTP_STATE_NONE);
			error = 1;
		}

		fbr_cstore_op_sync_free(sync);
	}

	if (request->state == CHTTP_STATE_NONE) {
		chttp_context_free(request);
		return error;
	}

	fbr_rlog(FBR_LOG_CS_S3, "S3 response: %d (%d %d %s)", request->status, request->state,
		request->error, chttp_error_msg(request));

	if (request->error || request->status != 200) {
		error = 1;
	} else {
		error = 0;
	}

	chttp_context_free(request);

	return error;
}

static void
_s3_wbuffer_data_cb(struct chttp_context *request, void *arg)
{
	chttp_context_ok(request);
	assert(arg);

	struct fbr_wbuffer *wbuffer = arg;
	fbr_wbuffer_ok(wbuffer);

	chttp_body_send(request, wbuffer->buffer, wbuffer->end);
	assert_zero(request->length);
}

void
fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *request,
    const char *path, struct fbr_wbuffer *wbuffer)
{
	int error = _s3_send_put(cstore, request, path, wbuffer->end, wbuffer->id, 0,
		_s3_wbuffer_data_cb, wbuffer, 0);
	if (error < 0) {
		chttp_context_reset(request);
		error = _s3_send_put(cstore, request, path, wbuffer->end, wbuffer->id, 0,
			_s3_wbuffer_data_cb, wbuffer, 1);
		assert_dev(error >= 0);
	}
}

void
fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct fbr_cstore_op_sync *sync, struct chttp_context *request, struct fbr_wbuffer *wbuffer,
    int error)
{
	fbr_fs_ok(fs);
	fbr_wbuffer_ok(wbuffer);

	error = fbr_cstore_s3_send_finish(cstore, sync, request, error);
	if (error) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
	}
}

static inline void
_s3_chunk_read_error(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_cstore_entry *entry,
    struct fbr_file *file, struct fbr_chunk *chunk, struct chttp_context *request)
{
	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);

	fbr_cstore_set_error(entry);
	fbr_cstore_release(cstore, entry);

	chttp_context_free(request);
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
	struct chttp_context request;

	while (retries <= 1) {
		chttp_context_init(&request);

		if (retries) {
			request.new_conn = 1;
		}
		retries++;

		fbr_cstore_s3_send_get(cstore, &request, path, chunk->id, retries);
		if (request.error) {
			continue;
		}

		break;
	}

	if (request.error || request.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp: %d %d", request.error, request.status);
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &request);
		return;
	} else if (!request.chunked && (size_t)request.length != chunk->length) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp length");
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &request);
		return;
	}

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	size_t bytes = 0;
	while (bytes < chunk->length) {
		bytes += chttp_body_read(&request, chunk->data + bytes, chunk->length - bytes);

		if (request.error || request.state >= CHTTP_STATE_IDLE) {
			break;
		}
	}

	if (request.error || bytes != chunk->length || request.state < CHTTP_STATE_IDLE) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR chttp bytes");
		_s3_chunk_read_error(fs, cstore, entry, file, chunk, &request);
		return;
	}

	chttp_context_free(&request);

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
_s3_writer_data_cb(struct chttp_context *request, void *arg)
{
	chttp_context_ok(request);
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
			chttp_body_send(request, output->buffer, output->buffer_pos);
			if (request->error) {
				return;
			}
		}

		output = output->next;
	}

	assert_zero(request->length);
}

void
fbr_cstore_s3_index_send(struct fbr_cstore *cstore, struct chttp_context *request,
    const char *path, struct fbr_writer *writer, fbr_id_t id)
{
	int error = _s3_send_put(cstore, request, path, writer->bytes, id, 0,
		_s3_writer_data_cb, writer, 0);
	if (error < 0) {
		chttp_context_reset(request);
		error = _s3_send_put(cstore, request, path, writer->bytes, id, 0,
			_s3_writer_data_cb, writer, 1);
		assert_dev(error >= 0);
	}
}

int
fbr_cstore_s3_get(struct fbr_cstore *cstore, fbr_hash_t hash, const char *file_path, fbr_id_t id,
    size_t size, enum fbr_cstore_entry_type type)
{
	fbr_cstore_ok(cstore);
	assert(file_path);
	assert(id);
	assert(size);
	assert(type > FBR_CSTORE_FILE_NONE && type <= FBR_CSTORE_FILE_ROOT);

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
	struct chttp_context request;

	while (retries <= 1) {
		chttp_context_init(&request);

		if (retries) {
			request.new_conn = 1;
		}
		retries++;

		fbr_cstore_s3_send_get(cstore, &request, file_path, id, retries);
		if (request.error) {
			continue;
		}

		break;
	}

	if (request.error || request.status != 200) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET: %d %d", request.error, request.status);
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&request);
		return 1;
	} else if (!request.chunked && (size_t)request.length != size) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET length");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&request);
		return 1;
	}

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&request);
		return 1;
	}

	size_t bytes = fbr_cstore_s3_splice(cstore, &request, fd, size);

	assert_zero(close(fd));

	if (bytes != size) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR S3_GET bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		chttp_context_free(&request);
		return 1;
	} else {
		assert_dev(request.state >= CHTTP_STATE_IDLE);
		assert_zero_dev(request.length);
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = id;
	metadata.size = size;
	metadata.type = type;
	metadata.gzipped = request.gzip;
	fbr_strbcpy(metadata.path, file_path);

	chttp_context_free(&request);

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

	struct chttp_context request;
	chttp_context_init(&request);

	int error = _s3_send_put(cstore, &request, root_path, root_json->bytes, version, existing,
		_s3_writer_data_cb, root_json, 0);
	if (error < 0) {
		chttp_context_reset(&request);
		error =_s3_send_put(cstore, &request, root_path, root_json->bytes, version,
			existing, _s3_writer_data_cb, root_json, 1);
		assert_dev(error >= 0);
	}

	error = fbr_cstore_s3_send_finish(cstore, NULL, &request, error);
	if (error) {
		return error;
	}

	fbr_cstore_async_root_write(cstore, root_json, root_path, version);

	return 0;
}
