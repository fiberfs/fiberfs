/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

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

void
fbr_cstore_s3_init(struct fbr_cstore *cstore, const char *host, int port, int tls,
    const char *prefix)
{
	fbr_cstore_ok(cstore);
	assert(host && *host);
	assert(port > 0 && port <= USHRT_MAX);

	struct fbr_cstore_s3 *s3 = &cstore->s3;
	assert_zero(s3->enabled);

	fbr_zero(s3);
	s3->host = strdup(host);
	s3->host_len = strlen(s3->host);
	s3->port = port;
	s3->tls = tls ? 1 : 0;
	s3->enabled = 1;

	if (prefix) {
		s3->prefix_len = strlen(prefix);
		if (s3->prefix_len >= 2 && prefix[0] == '/' && prefix[1] != '/') {
			s3->prefix = strdup(prefix);
			while (s3->prefix[s3->prefix_len - 1] == '/') {
				s3->prefix[s3->prefix_len - 1] = '\0';
				s3->prefix_len --;
				assert(s3->prefix_len);
			}
		} else {
			s3->prefix_len = 0;
		}
	}
}

void
fbr_cstore_s3_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_s3 *s3 = &cstore->s3;

	if (!s3->enabled) {
		return;
	}

	free(s3->host);
	free(s3->prefix);

	fbr_zero(s3);
}

void
fbr_cstore_cluster_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	assert_zero_dev(cstore->cluster.backends);
	assert_zero_dev(cstore->cluster.size);
}

void
fbr_cstore_cluster_add(struct fbr_cstore *cstore, const char *host, int port, int tls)
{
	fbr_cstore_ok(cstore);
	assert(host);
	assert(port > 0 && port <= USHRT_MAX);

	size_t host_len = strlen(host);
	struct fbr_cstore_backend *backend = malloc(sizeof(*backend) + host_len + 1);
	assert(backend);

	fbr_zero(backend);
	backend->magic = FBR_CSTORE_BACKEND_MAGIC;
	backend->port = port;
	backend->tls = tls ? 1 : 0;

	fbr_strcpy(backend->host, host_len + 1, host);

	fbr_cstore_backend_ok(backend);

	struct fbr_cstore_cluster *cluster = &cstore->cluster;
	cluster->size++;
	assert(cluster->size < 100000);
	cluster->backends = realloc(cluster->backends, sizeof(backend) * cluster->size);
	assert(cluster->backends);

	cluster->backends[cluster->size - 1] = backend;
}

void
fbr_cstore_cluster_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_cluster *cluster = &cstore->cluster;
	for (size_t i = 0; i < cluster->size; i++) {
		struct fbr_cstore_backend *backend = cluster->backends[i];
		fbr_cstore_backend_ok(backend);

		fbr_zero(backend);
		free(backend);
		cluster->backends[i] = NULL;
	}

	free(cluster->backends);
	fbr_zero(cluster);
}

static void
_s3_request_url(struct fbr_cstore *cstore, const char *path, struct chttp_context *request)
{
	assert_dev(cstore);
	assert_dev(cstore->s3.enabled);
	assert_dev(cstore->s3.host);
	assert_dev(path);
	assert_dev(request);

	char buffer[FBR_PATH_MAX];
	fbr_cstore_s3_url(cstore, path, buffer, sizeof(buffer));

	chttp_set_url(request, buffer);
	chttp_header_add(request, "Host", cstore->s3.host);
}

static void
_s3_request_url_chunk(struct fbr_cstore *cstore, struct fbr_file *file, struct fbr_chunk *chunk,
    struct chttp_context *request)
{
	assert_dev(cstore);
	assert_dev(file);
	assert_dev(chunk);
	assert_dev(request);

	char buffer[FBR_PATH_MAX];
	fbr_cstore_path_chunk(NULL, file, chunk->id, chunk->offset, 0, buffer, sizeof(buffer));

	_s3_request_url(cstore, buffer, request);
}

void
fbr_cstore_s3_delete(struct fbr_cstore *cstore, const char *s3_url, fbr_id_t id)
{
	fbr_cstore_ok(cstore);
	assert(s3_url);

	if (!cstore->s3.enabled) {
		return;
	}

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);

	int retries = 0;
	struct chttp_context request;

	while (retries <= 1) {
		chttp_context_init(&request);

		if (retries) {
			request.new_conn = 1;
		}
		retries++;

		chttp_set_method(&request, "DELETE");
		chttp_set_url(&request, s3_url);
		chttp_header_add(&request, "Host", cstore->s3.host);

		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "S3 DELETE %s (%d)",
			s3_url, retries);

		char buffer[32];
		fbr_cstore_etag(id, buffer, sizeof(buffer));
		chttp_header_add(&request, "ETag", buffer);

		chttp_connect(&request, cstore->s3.host, strlen(cstore->s3.host), cstore->s3.port,
			cstore->s3.tls);
		if (request.error) {
			fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
				"ERROR chttp connection %s", cstore->s3.host);
			return;
		}

		chttp_send(&request);
		if (request.error) {
			fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
				"ERROR chttp send: %s", chttp_error_msg(&request));
			continue;
		}

		chttp_receive(&request);
		if (request.error) {
			fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
				"ERROR chttp recv: %s", chttp_error_msg(&request));
			continue;
		}

		break;
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "S3 DELETE %d %d",
			request.error, request.status);

	if (request.error || request.status != 200) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
			"ERROR chttp: %d %d", request.error, request.status);
		return;
	}
}

static int
_s3_send_put(struct fbr_cstore *cstore, struct chttp_context *request,
    const char *path, size_t length, fbr_id_t etag, fbr_cstore_s3_put_f data_cb, void *put_arg,
    int retry)
{
	fbr_cstore_ok(cstore);
	assert_dev(cstore->s3.enabled);
	chttp_context_ok(request);
	assert_dev(request->state == CHTTP_STATE_NONE);
	assert_dev(path);
	assert_dev(length);
	assert_dev(etag);
	assert_dev(data_cb);

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);

	// TODO
	request->addr.timeout_connect_ms = 3000;
	request->addr.timeout_transfer_ms = 5000;

	if (retry) {
		request->new_conn = 1;
	}

	chttp_set_method(request, "PUT");
	_s3_request_url(cstore, path, request);

	chttp_dpage_ok(request->dpage);
	int url_len = 4;
	while (request->dpage->data[url_len] > ' ') {
		url_len++;
	}
	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "S3 %.*s (retry: %d)",
		url_len, request->dpage->data, retry);

	char buffer[32];
	fbr_bprintf(buffer, "%zu", length);

	chttp_header_add(request, "Content-Length", buffer);
	chttp_header_add(request, "If-None-Match", "*");

	fbr_cstore_etag(etag, buffer, sizeof(buffer));
	chttp_header_add(request, "ETag", buffer);

	chttp_connect(request, cstore->s3.host, strlen(cstore->s3.host), cstore->s3.port,
		cstore->s3.tls);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id,
			"ERROR chttp connection %s", cstore->s3.host);
		return 1;
	}

	chttp_send(request);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "ERROR chttp send");
		// Retry
		if (request->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}

	data_cb(request, put_arg);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "ERROR chttp body");
		// Retry
		if (request->addr.reused && !retry) {
			return -1;
		}
		return 1;
	}
	assert_zero_dev(request->length);

	chttp_receive(request);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "ERROR chttp receive");
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
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "ERROR chttp rbody");
		return 1;
	}

	return 0;
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
	int ret = _s3_send_put(cstore, request, path, wbuffer->end, wbuffer->id,
		_s3_wbuffer_data_cb, wbuffer, 0);
	if (ret < 0) {
		chttp_context_reset(request);
		ret = _s3_send_put(cstore, request, path, wbuffer->end, wbuffer->id,
			_s3_wbuffer_data_cb, wbuffer, 1);
		assert_dev(ret >= 0);
	}
}

static void *
_io_thread_wbuffer_send(void *arg)
{
	assert(arg);

	struct fbr_cstore_op *op = arg;
	fbr_cstore_op_ok(op);
	assert(op->type == FBR_CSOP_WBUFFER_SEND);

	fbr_cstore_s3_wbuffer_send(op->param0, op->param1, op->param2, op->param3);

	return NULL;
}

pthread_t
fbr_cstore_s3_wbuffer_send_async(struct fbr_cstore *cstore, struct chttp_context *request,
    char *path, struct fbr_wbuffer *wbuffer, struct fbr_cstore_op *op)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_op_ok(op);

	if (!cstore->s3.enabled) {
		return 0;
	}

	/*
	if (fbr_is_test()) {
		fbr_cstore_s3_wbuffer_send(cstore, request, path, wbuffer);
		return 0;
	}
	*/

	fbr_zero(op);
	op->magic = FBR_CSTORE_OP_MAGIC;
	op->type = FBR_CSOP_WBUFFER_SEND;
	op->param0 = cstore;
	op->param1 = request;
	op->param2 = path;
	op->param3 = wbuffer;

	pthread_t s3_thread = 0;
	pt_assert(pthread_create(&s3_thread, NULL, _io_thread_wbuffer_send, op));
	assert(s3_thread);

	return s3_thread;
}

void
fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
    pthread_t s3_thread, struct chttp_context *request, struct fbr_wbuffer *wbuffer, int error)
{
	fbr_fs_ok(fs);
	fbr_cstore_ok(cstore);
	chttp_context_ok(request);
	fbr_wbuffer_ok(wbuffer);

	if (s3_thread) {
		pt_assert(pthread_join(s3_thread, NULL));
	}

	if (request->state == CHTTP_STATE_NONE) {
		assert_zero_dev(s3_thread);
		if (error) {
			fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		} else {
			fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
		}
		chttp_context_free(request);
		return;
	}

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "S3 response: %d (%d %d %s)",
		request->status, request->state, request->error, chttp_error_msg(request));

	if (request->error || request->status != 200) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
	}

	chttp_context_free(request);;
}

static inline void
_s3_chunk_error(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_cstore_entry *entry,
    struct fbr_file *file, struct fbr_chunk *chunk, struct chttp_context *request)
{
	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);

	fbr_cstore_set_error(entry);
	fbr_cstore_release(cstore, entry);

	chttp_context_free(request);
}

static inline void
_s3_chunk_write_error(struct fbr_fs *fs, struct fbr_cstore *cstore, struct fbr_cstore_entry *entry,
    struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_file_LOCK(fs, file);
	fbr_chunk_release(chunk);
	fbr_file_UNLOCK(file);
	fbr_inode_release(fs, &file);

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

	if (!cstore->s3.enabled) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, chunk->id, chunk->offset);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, chunk->length,
		NULL, 1);
	if (!entry) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR s3 loading state");
		return;
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

		chttp_set_method(&request, "GET");
		_s3_request_url_chunk(cstore, file, chunk, &request);

		chttp_dpage_ok(request.dpage);
		int url_len = 4;
		while (request.dpage->data[url_len] > ' ') {
			url_len++;
		}
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "S3 %.*s (retry: %d)",
			url_len, request.dpage->data, retries - 1);

		char buffer[32];
		fbr_cstore_etag(chunk->id, buffer, sizeof(buffer));
		chttp_header_add(&request, "If-Match", buffer);

		chttp_connect(&request, cstore->s3.host, strlen(cstore->s3.host), cstore->s3.port,
			cstore->s3.tls);
		if (request.error) {
			_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
			fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
				"ERROR chttp connection %s", cstore->s3.host);
			return;
		}

		chttp_send(&request);
		if (request.error) {
			fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
				"ERROR chttp send: %s", chttp_error_msg(&request));
			continue;
		}

		chttp_receive(&request);
		if (request.error) {
			fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
				"ERROR chttp recv: %s", chttp_error_msg(&request));
			continue;
		}

		break;
	}

	if (request.error || request.status != 200) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
			"ERROR chttp: %d %d", request.error, request.status);
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
		return;
	} else if (!request.chunked && (size_t)request.length != chunk->length) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp length");
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
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
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp bytes");
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
		return;
	}

	chttp_context_free(&request);

	// Take a chunk ref and write it to the cstore

	fbr_file_ref_inode(fs, file);
	fbr_file_LOCK(fs, file);
	fbr_chunk_take(chunk);
	fbr_file_UNLOCK(file);

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "WRITE S3 chunk: %s",
		path);

	int ret = fbr_sys_mkdirs(path);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR write mkdir");
		_s3_chunk_write_error(fs, cstore, entry, file, chunk);
		return;
	}

	if (fbr_sys_exists(path)) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR write exists");
		_s3_chunk_write_error(fs, cstore, entry, file, chunk);
		return;
	}

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR write open()");
		_s3_chunk_write_error(fs, cstore, entry, file, chunk);
		return;
	}

	bytes = fbr_sys_write(fd, chunk->data, chunk->length);
	assert_zero(close(fd));

	if (bytes != chunk->length) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR write bytes");
		_s3_chunk_write_error(fs, cstore, entry, file, chunk);
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
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR write metadata");
		_s3_chunk_write_error(fs, cstore, entry, file, chunk);
		return;
	}

	fbr_file_LOCK(fs, file);
	fbr_chunk_release(chunk);
	fbr_file_UNLOCK(file);
	fbr_inode_release(fs, &file);

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
    const char *url, struct fbr_writer *writer, fbr_id_t id)
{
	int ret = _s3_send_put(cstore, request, url, writer->bytes, id,
		_s3_writer_data_cb, writer, 0);
	if (ret < 0) {
		chttp_context_reset(request);
		ret = _s3_send_put(cstore, request, url, writer->bytes, id,
			_s3_writer_data_cb, writer, 0);
		assert_dev(ret >= 0);
	}
}
