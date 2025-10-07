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

void
fbr_cstore_s3_init(struct fbr_cstore_s3 *s3, const char *host, int port, int tls,
    const char *prefix)
{
	assert(s3);
	assert(host);
	assert(port > 0 && port <= USHRT_MAX);

	fbr_zero(s3);

	s3->host = strdup(host);
	s3->port = port;
	s3->tls = tls ? 1 : 0;
	s3->enabled = 1;

	if (prefix) {
		s3->prefix = strdup(prefix);
	}
}

void
fbr_cstore_s3_free(struct fbr_cstore_s3 *s3)
{
	assert(s3);

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
_s3_write_url(struct fbr_cstore *cstore, const char *path, struct chttp_context *request)
{
	assert_dev(cstore);
	assert_dev(path);
	assert_dev(request);

	char buffer[FBR_PATH_MAX];
	fbr_bprintf(buffer, "%s/%s", cstore->s3.prefix, path);

	chttp_set_url(request, buffer);
}

static void
_s3_write_file_url(struct fbr_cstore *cstore, struct fbr_file *file, struct chttp_context *request)
{
	assert_dev(cstore);
	assert_dev(file);
	assert_dev(request);

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	_s3_write_url(cstore, filepath.name, request);
}

void
fbr_cstore_s3_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *request,
    const char *path, struct fbr_wbuffer *wbuffer)
{
	fbr_cstore_ok(cstore);
	assert(cstore->s3.enabled);
	chttp_context_ok(request);
	assert(path);
	fbr_wbuffer_ok(wbuffer);

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);

	chttp_set_method(request, "PUT");
	_s3_write_url(cstore, path, request);

	char buffer[32];
	fbr_bprintf(buffer, "%zu", wbuffer->end);

	chttp_header_add(request, "Content-Length", buffer);

	// TODO conditionals

	chttp_connect(request, cstore->s3.host, strlen(cstore->s3.host), cstore->s3.port,
		cstore->s3.tls);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id,
			"ERROR chttp connection %s", cstore->s3.host);
		return;
	}

	chttp_send(request);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "ERROR chttp send");
		return;
	}

	chttp_body_send(request, wbuffer->buffer, wbuffer->end);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "ERROR chttp body");
		return;
	}

	assert_zero_dev(request->length);
	assert_dev(request->state == CHTTP_STATE_SENT);
}

void
fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
    struct chttp_context *request, struct fbr_wbuffer *wbuffer, int error)
{
	fbr_fs_ok(fs);
	fbr_cstore_ok(cstore);
	chttp_context_ok(request);
	fbr_wbuffer_ok(wbuffer);

	if (request->state == CHTTP_STATE_NONE) {
		if (error) {
			fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		} else {
			fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
		}
		chttp_context_free(request);
		return;
	} else if (request->state != CHTTP_STATE_SENT) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		chttp_context_free(request);
		return;
	}

	chttp_receive(request);

	if (request->error || request->status != 200) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
	}

	chttp_context_free(request);
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
	fbr_hash_t hash = fbr_cstore_hash_chunk(fs, file, chunk->id, chunk->offset);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, chunk->length,
		NULL, 1);
	if (!entry) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR s3 loading state");
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	struct chttp_context request;
	chttp_context_init(&request);

	chttp_set_method(&request, "GET");
	_s3_write_file_url(cstore, file, &request);

	// TODO headers

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
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp send");
		return;
	}

	chttp_receive(&request);

	if (request.error || request.status != 200) {
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp response");
		return;
	} else if (!request.chunked && (size_t)request.length != chunk->length) {
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp length");
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
		_s3_chunk_error(fs, cstore, entry, file, chunk, &request);
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp bytes");
		return;
	}

	fbr_file_ref_inode(fs, file);
	fbr_file_LOCK(fs, file);
	fbr_chunk_take(chunk);
	fbr_file_UNLOCK(file);

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);

	// TODO write chunk here

	fbr_file_LOCK(fs, file);
	fbr_chunk_release(chunk);
	fbr_file_UNLOCK(file);
	fbr_inode_release(fs, &file);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	chttp_context_free(&request);
}
