/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"

void
fbr_cmd_cstore_backend_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	char *root = fbr_test_mkdir_tmp(ctx, NULL);
	struct fbr_cstore _cstore, *cstore;
	struct fbr_cstore_backend *backend;

	cstore = fbr_cstore_alloc(root);
	assert_zero(fbr_cstore_backend_enabled(cstore));
	fbr_cstore_s3_init(cstore, "s3host", 443, 1, NULL, "reg", "akey", "skey");
	assert(fbr_cstore_backend_enabled(cstore));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	assert(backend->port == 443);
	assert(backend->tls);
	assert_zero(cstore->s3.prefix);
	assert_zero(strcmp(cstore->s3.region, "reg"));
	assert_zero(strcmp(cstore->s3.access_key, "akey"));
	assert_zero(strcmp(cstore->s3.secret_key, "skey"));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CDN, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_S3, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	fbr_cstore_free(cstore);

	cstore = &_cstore;

	fbr_cstore_init(cstore, root);
	assert_zero(fbr_cstore_backend_enabled(cstore));
	fbr_cstore_s3_init(cstore, "s3host", 80, 0, "/prefix", "reg", "akey", "skey");
	assert(fbr_cstore_backend_enabled(cstore));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	assert(backend->port == 80);
	assert_zero(backend->tls);
	assert_zero(strcmp(cstore->s3.prefix, "/prefix"));
	fbr_cstore_free(cstore);

	fbr_cstore_init(cstore, root);
	fbr_cstore_s3_init(cstore, "s3host", 80, 0, "/prefix", "reg", "akey", "skey");
	fbr_cstore_cluster_add(&cstore->cluster, "cluster1", 8888, 0);
	fbr_cstore_cluster_add(&cstore->cluster, "cluster2", 8888, 0);
	fbr_cstore_cluster_add(&cstore->cluster, "cluster3", 8888, 0);
	fbr_cstore_cluster_add(&cstore->cdn, "cdn", 443, 1);
	assert(fbr_cstore_backend_enabled(cstore));
	backend = fbr_cstore_backend_get(cstore, fbr_hash("/123", 4),
		FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strncmp(backend->host, "cluster", 7));
	assert(backend->port == 8888);
	assert_zero(backend->tls);
	fbr_test_logs("Cluster backend: %s", backend->host);
	const char *b123 = backend->host;
	backend = fbr_cstore_backend_get(cstore, fbr_hash("/124", 4),
		FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	assert_zero(strncmp(backend->host, "cluster", 7));
	fbr_test_logs("Cluster backend: %s", backend->host);
	backend = fbr_cstore_backend_get(cstore, fbr_hash("/125", 4),
		FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	assert_zero(strncmp(backend->host, "cluster", 7));
	fbr_test_logs("Cluster backend: %s", backend->host);
	backend = fbr_cstore_backend_get(cstore, fbr_hash("/126", 4),
		FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	assert_zero(strncmp(backend->host, "cluster", 7));
	fbr_test_logs("Cluster backend: %s", backend->host);
	backend = fbr_cstore_backend_get(cstore, fbr_hash("/123", 4),
		FBR_CSTORE_ROUTE_CLUSTER, 1, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strncmp(backend->host, "cluster", 7));
	fbr_test_logs("Cluster backend: %s (not %s)", backend->host, b123);
	assert(backend->host != b123);
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CDN, 0, 1);
	assert_zero(strcmp(backend->host, "cdn"));
	assert(backend->port == 443);
	assert(backend->tls);
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_S3, 0, 1);
	assert_zero(strcmp(backend->host, "s3host"));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CDN, 0, 0);
	assert_zero(strcmp(backend->host, "s3host"));
	fbr_cstore_free(cstore);

	fbr_cstore_init(cstore, root);
	fbr_cstore_s3_init(cstore, "s3host", 80, 0, "/prefix", "reg", "akey", "skey");
	for (size_t i = 0; i < 128; i++) {
		char hostbuf[32];
		fbr_bprintf(hostbuf, "cluster_%zu", i);
		fbr_cstore_cluster_add(&cstore->cluster, hostbuf, 80, 0);
	}
	fbr_test_logs("cstore->cluster.size: %zu", cstore->cluster.size);
	struct fbr_cstore_worker *worker = NULL;
	for (size_t i = 0; i < 16; i++) {
		if (i == 8) {
			worker = fbr_cstore_worker_alloc(cstore, __func__);
			fbr_cstore_worker_ok(worker);
			fbr_cstore_worker_init(worker, NULL);
		}
		char url[32];
		size_t url_len = fbr_bprintf(url, "/123_%zu", i);
		backend = fbr_cstore_backend_get(cstore, fbr_hash(url, url_len),
			FBR_CSTORE_ROUTE_CLUSTER, 1, 1);
		assert_zero(strncmp(backend->host, "cluster", 7));
		fbr_test_logs("Cluster backend %s: %s", url, backend->host);
	}
	fbr_cstore_worker_finish(worker);
	fbr_cstore_worker_free(worker);
	fbr_cstore_free(cstore);

	fbr_test_logs("cstore_backend_test done");
}
