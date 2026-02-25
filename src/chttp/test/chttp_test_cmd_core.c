/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "compress/fbr_gzip.h"
#include "dns/chttp_dns.h"
#include "tls/chttp_tls.h"

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

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

	fbr_zero(ctx->chttp_test);
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
	struct fbr_test *test = fbr_test_convert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	fbr_test_ERROR(test->cmd_count != 1, "test file must begin with chttp_test");

	fbr_test_unescape(&cmd->params[0]);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
chttp_test_cmd_connect_or_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	char *host = cmd->params[0].value;
	long port = fbr_test_parse_long(cmd->params[1].value);
	fbr_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	struct chttp_addr addr;
	int ret = chttp_dns_resolve(&addr, host, strlen(host), port, 0);

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

char *
chttp_test_var_tls_enabled(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (chttp_tls_enabled()) {
		return "1";
	} else {
		return "0";
	}
}
