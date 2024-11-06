/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "compress/chttp_gzip.h"
#include "dns/chttp_dns.h"
#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"
#include "tls/chttp_tls.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static void
_finish_test(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	fbr_test_ERROR(ctx->chttp_test->chttp != NULL, "chttp context detected");
	fbr_test_ERROR(ctx->chttp_test->server != NULL, "chttp server detected");
	fbr_test_ERROR(ctx->chttp_test->dns != NULL, "dns detected");
	fbr_test_ERROR(ctx->chttp_test->tcp_pool != NULL, "tcp_pool detected");
	fbr_test_ERROR(ctx->chttp_test->gzip != NULL, "gzip detected");

	chttp_ZERO(ctx->chttp_test);
	free(ctx->chttp_test);
	ctx->chttp_test = NULL;
}

void
chttp_test_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert_zero(ctx->chttp_test);

	ctx->chttp_test = calloc(1, sizeof(*ctx->chttp_test));
	assert(ctx->chttp_test);

	ctx->chttp_test->magic = CHTTP_TEST_CONTEXT_MAGIC;

	fbr_test_register_finish(ctx, "chttp_context", _finish_test);
}

void
chttp_test_cmd_chttp_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test;

	test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	fbr_test_ERROR(test->cmds != 1, "test file must begin with chttp_test");

	fbr_test_unescape(&cmd->params[0]);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
chttp_test_cmd_connect_or_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_addr addr;
	char *host;
	long port;
	int ret;

	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	host = cmd->params[0].value;
	port = fbr_test_parse_long(cmd->params[1].value);
	fbr_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	ret = chttp_dns_resolve(&addr, host, strlen(host), port, 0);

	if (ret) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "cannot connect to %s:%ld", host, port);
		return;
	}

	ret = chttp_tcp_connect(&addr);

	if (ret) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "cannot connect to %s:%ld", host, port);
		return;
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "valid address found %s:%ld", host, port);

	chttp_tcp_close(&addr);

	return;
}

void
chttp_test_cmd_tls_or_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (chttp_tls_enabled()) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "TLS is supported");
		return;
	} else {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "TLS not configured");
		return;
	}
}

void
chttp_test_cmd_gzip_or_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (chttp_gzip_enabled()) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "gzip is supported");
		return;
	} else {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "gzip not configured");
		return;
	}
}
