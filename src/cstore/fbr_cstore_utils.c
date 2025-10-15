/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "server/fbr_cstore_server.h"
#include "core/fuse/fbr_fuse.h"
#include "core/store/fbr_store.h"

struct fbr_cstore_config _CSTORE_CONFIG = {
	FBR_CSTORE_ASYNC_THREAD_DEFAULT,
	FBR_CSTORE_LOAD_THREAD_DEFAULT,
	0,
	FBR_CSTORE_SERVER_ADDRESS,
	FBR_CSTORE_SERVER_PORT,
	0,
	FBR_CSTORE_WORKERS_DEFAULT,
	FBR_CSTORE_WORKERS_ACCEPT_DEFAULT
};

static const struct fbr_store_callbacks _CSTORE_DEFAULT_CALLBACKS = {
	.chunk_read_f = fbr_cstore_async_chunk_read,
	.chunk_delete_f = fbr_cstore_async_chunk_delete,
	.wbuffer_write_f = fbr_cstore_async_wbuffer_write,
	.index_write_f = fbr_cstore_index_root_write,
	.index_read_f = fbr_cstore_index_read,
	.index_delete_f = fbr_cstore_index_delete,
	.root_read_f = fbr_cstore_root_read
};
const struct fbr_store_callbacks *FBR_CSTORE_DEFAULT_CALLBACKS = &_CSTORE_DEFAULT_CALLBACKS;

void
fbr_cstore_fuse_register(const char *root_path)
{
	assert(root_path);
	assert(fbr_fuse_has_context());

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	assert_zero(fuse_ctx->cstore);

	fuse_ctx->cstore = fbr_cstore_alloc(root_path);
	fbr_cstore_ok(fuse_ctx->cstore);
}

struct fbr_cstore *
fbr_cstore_find(void)
{
	if (fbr_fuse_has_context()) {
		struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
		if (fuse_ctx->cstore) {
			return fuse_ctx->cstore;
		}
	}

	return NULL;
}

size_t
fbr_cstore_etag(fbr_id_t id, char *buffer, size_t buffer_len)
{
	assert(buffer);
	assert(buffer_len >= FBR_ID_STRING_MAX + 2);

	buffer[0] = '\"';
	size_t len = 1 + fbr_id_string(id, buffer + 1, buffer_len - 2);
	buffer[len++] = '\"';
	buffer[len] = '\0';

	return len;
}

const char *
fbr_cstore_type_name(enum fbr_cstore_entry_type type)
{
	switch (type) {
		case FBR_CSTORE_FILE_NONE:
			return "NONE";
		case FBR_CSTORE_FILE_CHUNK:
			return "CHUNK";
		case FBR_CSTORE_FILE_INDEX:
			return "INDEX";
		case FBR_CSTORE_FILE_ROOT:
			return "ROOT";
	}

	return "ERROR";
}
