/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

void
_s3_write_url(struct fbr_cstore *cstore, const char *path, struct chttp_context *request)
{
	assert_dev(cstore);
	assert_dev(path);
	assert_dev(request);

	char buffer[FBR_PATH_MAX];
	fbr_bprintf(buffer, "%s/%s", cstore->s3.prefix, path);

	chttp_set_url(request, buffer);
}

void
fbr_cstore_s3_wbuffer_write(struct fbr_cstore *cstore, struct chttp_context *request,
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

	chttp_connect(request, cstore->s3.host, strlen(cstore->s3.host), cstore->s3.port,
		cstore->s3.tls);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id,
			"ERROR chttp connection %s", cstore->s3.host);
		return;
	}

	chttp_send(request);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp send");
		return;
	}

	chttp_body_send(request, wbuffer->buffer, wbuffer->end);
	if (request->error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR chttp body");
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
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR s3 loading state");
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	// TODO ok
	fbr_cstore_set_error(entry);
	fbr_cstore_release(cstore, entry);

	// TODO READY
	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
}
