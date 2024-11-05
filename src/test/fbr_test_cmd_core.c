/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "compress/chttp_gzip.h"
#include "dns/chttp_dns.h"
#include "test/fbr_test.h"
#include "tls/chttp_tls.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

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
chttp_test_cmd_sleep_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long ms;

	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	ms = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(ms < 0, "invalid sleep time");

	fbr_test_sleep_ms(ms);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "slept %ldms", ms);
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
chttp_test_cmd_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int ret;

	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	fbr_test_ERROR(ret, "not equal '%s' != '%s'", cmd->params[0].value, cmd->params[1].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "equal '%s'", cmd->params[0].value);
}

void
chttp_test_cmd_not_equal(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int ret;

	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	fbr_test_ERROR(!ret, "equal '%s' == '%s'", cmd->params[0].value, cmd->params[1].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "not equal '%s' != '%s'", cmd->params[0].value,
		cmd->params[1].value);
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

void
chttp_test_cmd_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_skip(ctx);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "Skipping");
}
