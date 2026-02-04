/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <string.h>

#include "fiberfs.h"
#include "utils/fbr_chash.h"

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

void
chttp_test_md5_store(struct fbr_md5_ctx *md5, char *buffer, size_t buffer_len)
{
	fbr_md5_ok(md5);
	assert(md5->ready);
	assert(buffer_len >= CHTTP_TEST_MD5_BUFLEN);

	fbr_bin2hex(md5->digest, sizeof(md5->digest), buffer, buffer_len);
}

void
chttp_test_md5_store_server(struct fbr_test_context *ctx, struct fbr_md5_ctx *md5)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	chttp_test_md5_store(md5, ctx->chttp_test->md5_server, sizeof(ctx->chttp_test->md5_server));
}

void
chttp_test_md5_store_client(struct fbr_test_context *ctx, struct fbr_md5_ctx *md5)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	chttp_test_md5_store(md5, ctx->chttp_test->md5_client, sizeof(ctx->chttp_test->md5_client));
}

char *
chttp_test_var_md5_server(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(strlen(ctx->chttp_test->md5_server) == 32);

	return ctx->chttp_test->md5_server;
}

char *
chttp_test_var_md5_client(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(strlen(ctx->chttp_test->md5_client) == 32);

	return ctx->chttp_test->md5_client;
}
