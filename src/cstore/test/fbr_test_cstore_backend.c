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
	struct fbr_cstore _cstore, *cstore = &_cstore;
	struct fbr_cstore_backend *backend;

	fbr_cstore_init(cstore, root);
	assert_zero(fbr_cstore_backend_enabled(cstore));
	fbr_cstore_s3_init(cstore, "s3host", 443, 1, NULL, "region", "access_key", "secret_key");
	assert(fbr_cstore_backend_enabled(cstore));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CLUSTER, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	assert(backend->port == 443);
	assert(backend->tls);
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_CDN, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	backend = fbr_cstore_backend_get(cstore, 1, FBR_CSTORE_ROUTE_S3, 0, 1);
	fbr_cstore_backend_ok(backend);
	assert_zero(strcmp(backend->host, "s3host"));
	fbr_cstore_free(cstore);

	fbr_test_logs("cstore_backend_test done");
}
