/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "server/fbr_cstore_server.h"
#include "core/fuse/fbr_fuse.h"
#include "core/store/fbr_store.h"

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
fbr_cstore_config_load(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_config_reader *reader = &cstore->config.reader;
	fbr_config_reader_ok(reader);

	int locked = fbr_config_reader_lock(reader);
	if (!locked) {
		assert_dev(reader->init);
		return;
	}

	cstore->config.delete_cache = fbr_conf_get_bool("CSTORE_DELETE_CACHE", FBR_CONFIG_FALSE);
	cstore->config.allow_cdn_put = fbr_conf_get_bool("ALLOW_CDN_PUT", FBR_CONFIG_FALSE);
	cstore->config.allow_cdn_delete = fbr_conf_get_bool("ALLOW_CDN_DELETE", FBR_CONFIG_FALSE);
	cstore->config.force_chunk_write = fbr_conf_get_bool("FORCE_CHUNK_WRITE",
		FBR_CONFIG_FALSE);
	cstore->config.async_write = fbr_conf_get_bool("ASYNC_WRITE", FBR_CONFIG_TRUE);
	cstore->config.prune_attempts = fbr_conf_get_ulong("PRUNE_ATTEMPTS",
		FBR_CSTORE_PRUNE_ATTEMPTS);

	cstore->config.timeout_connect_ms = fbr_conf_get_ulong("HTTP_CONNECT_TIMEOUT_MSEC",
		FBR_CSTORE_TIMEOUT_CONNECT_MS);
	cstore->config.timeout_transfer_ms = fbr_conf_get_ulong("HTTP_TRANSFER_TIMEOUT_MSEC",
		FBR_CSTORE_TIMEOUT_TRANSFER_MS);
	cstore->config.keep_alive_sec = fbr_conf_get_ulong("HTTP_KEEP_ALIVE_SEC",
		FBR_CSTORE_KEEP_ALIVE_DEFAULT);

	cstore->config.retries = fbr_conf_get_ulong("HTTP_RETRIES", FBR_CSTORE_RETRIES_DEFAULT);
	cstore->config.cluster_retries = fbr_conf_get_ulong("HTTP_CLUSTER_RETRIES", 1);

	cstore->config.root_ttl_sec = fbr_conf_get_ulong("ROOT_FILE_TTL_SEC",
		FBR_CSTORE_ROOT_TTL_DEFAULT);

	fbr_config_reader_ready(reader);
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

#include "utils/fbr_enum_string.h"
FBR_ENUM_CSTORE_ENTRY_TYPE

void
fbr_cstore_request_id(char *buffer, size_t buffer_len)
{
	assert(buffer);
	assert(buffer_len >= 22);

	fbr_strcpy(buffer, buffer_len, "0");

	struct fbr_request *request = fbr_request_get();
	if (request) {
		fbr_snprintf(buffer, buffer_len, "%lu", request->id);
	} else {
		struct fbr_cstore_worker *worker = fbr_cstore_worker_get();
		if (worker) {
			fbr_snprintf(buffer, buffer_len, "%lu", worker->request_id);
		}
	}
}
