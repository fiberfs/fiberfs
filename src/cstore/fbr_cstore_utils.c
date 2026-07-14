/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "server/fbr_cstore_server.h"
#include "chttp/tls/chttp_tls.h"
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
	cstore->config.allow_cdn_root_get = fbr_conf_get_bool("ALLOW_CDN_ROOT_GET",
		FBR_CONFIG_FALSE);
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
	cstore->config.cluster_retries = fbr_conf_get_ulong("HTTP_CLUSTER_RETRIES",
		FBR_CSTORE_CLUSTER_RETRY_DEFAULT);

	cstore->config.root_ttl_sec = fbr_conf_get_ulong("ROOT_FILE_TTL_SEC",
		is_test ? FBR_ROOT_TTL_DEFAULT_TEST: FBR_ROOT_TTL_DEFAULT);

	fbr_config_reader_ready(reader);
}

static int
_parse_port(char *host, size_t host_len)
{
	assert_dev(host);
	assert_dev(host_len);

	for (size_t i = 0; i < host_len; i++) {
		if (host[i] == ':') {
			host[i] = '\0';

			const char *port_str = host + i + 1;
			size_t port_len = host_len - i - 1;

			if (!port_len) {
				return -1;
			}

			int error;
			long port = fbr_parse_long(port_str, port_len, &error);

			if (error || port < 1 || port > USHRT_MAX) {
				return -1;
			}

			return port;
		}
	}

	return 0;
}

static void
_cstore_parse_cluster(struct fbr_cstore *cstore, int cdn)
{
	assert_dev(cstore);

	const char *endpoints = fbr_conf_get(cdn ? "CDN_ENDPOINT" : "CLUSTER", NULL);
	if (!endpoints) {
		return;
	}

	const char *endpoint = NULL;
	size_t len;
	char host_buf[512];

	int tls = 0;
	if (cdn) {
		tls = fbr_conf_get_bool("CDN_TLS", FBR_CONFIG_TRUE);
	} else {
		tls = fbr_conf_get_bool("CLUSTER_TLS", FBR_CONFIG_FALSE);
	}

	while (fbr_csv_parse(endpoints, &endpoint, &len)) {
		assert_dev(endpoint);

		if (len >= sizeof(host_buf)) {
			fbr_rlog(FBR_LOG_MOUNT, "%s host too long: %.*s",
				cdn ? "CDN" : "Cluster", (int)len, endpoint);
			continue;
		}

		fbr_bprintf(host_buf, "%.*s", (int)len, endpoint);

		int port = _parse_port(host_buf, len);
		if (!port) {
			if (tls) {
				port = FBR_CSTORE_S3_DEFAULT_TLS_PORT;
			} else {
				port = FBR_CSTORE_S3_DEFAULT_PORT;
			}
		}

		fbr_rlog(FBR_LOG_MOUNT, "%s endpoint: %s port: %d tls: %d",
			cdn ? "CDN" : "Cluster", host_buf, port, tls);

		if (cdn) {
			fbr_cstore_cluster_add(&cstore->cdn, host_buf, port, tls);
		} else {
			fbr_cstore_cluster_add(&cstore->cluster, host_buf, port, tls);
		}
	}
}

int
fbr_cstore_autoinit(struct fbr_cstore *cstore)
{
	if (cstore) {
		fbr_cstore_ok(cstore);
	}

	int tls = chttp_tls_enabled();
	int error = 0;

	const char *s3_host = fbr_conf_get("S3_HOST", NULL);
	const char *s3_region = fbr_conf_get("S3_REGION", NULL);
	const char *s3_access_key = fbr_conf_get("S3_ACCESS_KEY", NULL);
	const char *s3_secret_key = fbr_conf_get("S3_SECRET_KEY", NULL);
	const char *s3_prefix = fbr_conf_get("S3_PREFIX", NULL);
	int s3_tls = fbr_conf_get_bool("S3_TLS",
		tls ? FBR_CSTORE_S3_DEFAULT_TLS : FBR_CONFIG_FALSE);

	int s3_port = fbr_conf_get_ulong("S3_PORT",
		tls ? FBR_CSTORE_S3_DEFAULT_TLS_PORT : FBR_CSTORE_S3_DEFAULT_PORT);
	if (s3_port > USHRT_MAX) {
		if (s3_tls) {
			s3_port = FBR_CSTORE_S3_DEFAULT_TLS_PORT;
		} else {
			s3_port = FBR_CSTORE_S3_DEFAULT_PORT;
		}
	}

	if (!s3_host || !s3_region || !s3_access_key || !s3_secret_key) {
		error = 1;
	}

	if (!cstore || error) {
		return error;
	}

	fbr_cstore_s3_init(cstore, s3_host, s3_port, s3_tls, s3_prefix, s3_region, s3_access_key,
		s3_secret_key);

	_cstore_parse_cluster(cstore, 0);
	_cstore_parse_cluster(cstore, 1);

	return 0;
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
