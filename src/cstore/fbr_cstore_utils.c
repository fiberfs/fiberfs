/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "server/fbr_cstore_server.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/store/fbr_store.h"
#include "utils/fbr_sys.h"

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

	int is_test = fbr_is_test();

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
		is_test ? FBR_ROOT_TTL_DEFAULT_TEST: FBR_ROOT_TTL_DEFAULT);

	fbr_config_reader_ready(reader);
}

void
fbr_cstore_gen_etag(struct fbr_etag *etag)
{
	assert(etag);

	fbr_id_t etag_id = fbr_id_gen();
	fbr_hash_t hash = fbr_hash(&etag_id, sizeof(etag_id));

	char hash_buf[FBR_HEX_LEN(sizeof(hash))];
	fbr_bin2hex(&hash, sizeof(hash), hash_buf, sizeof(hash_buf));

	etag->length = fbr_bprintf(etag->value, "\"%s\"", hash_buf);
	assert_dev(etag->length == strlen(etag->value));
}

void
fbr_cstore_etag_init(struct fbr_etag *etag, const char *etag_hdr)
{
	assert(etag);

	etag->length = 0;
	etag->value[0] = '\0';

	if (!etag_hdr) {
		return;
	}

	size_t etag_len = strlen(etag_hdr);
	if (etag_len >= sizeof(etag->value)) {
		return;
	}

	etag->length = fbr_strbcpy(etag->value, etag_hdr);
}

#include "utils/fbr_enum_string.h"
FBR_ENUM_CSTORE_FILE_TYPE

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

void
fbr_cstore_make_root(struct fbr_cstore_hashpath *cache_hashroot, const char *cache_root,
    const char *mount_path)
{
	assert(cache_hashroot);
	assert(cache_root);
	assert(mount_path);

	size_t mount_len = strlen(mount_path);
	assert(mount_len);

	char mount_hash_str[FBR_HASH_SLEN];
	fbr_hash_t mount_hash = fbr_hash(mount_path, mount_len);
	mount_len = fbr_bin2hex(&mount_hash, sizeof(mount_hash), mount_hash_str,
		sizeof(mount_hash_str));
	assert_dev(mount_len == FBR_HASH_SLEN - 1);

	const char *sep = "/";
	size_t root_len = strlen(cache_root);
	assert(root_len);
	if (cache_root[root_len - 1] == '/') {
		sep = "";
	}

	cache_hashroot->magic = FBR_CSTORE_HASHPATH_MAGIC;
	cache_hashroot->length = fbr_bprintf(cache_hashroot->value, "%s%s%s/",
		cache_root, sep, mount_hash_str);

	fbr_cstore_hashpath_ok(cache_hashroot);

	int fail = fbr_sys_mkdirs(cache_hashroot->value);
	fbr_ASSERT(!fail, "mkdir() failed: %s", cache_hashroot->value);
}
