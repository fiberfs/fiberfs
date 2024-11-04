/*
 * Copyright (c) 2021 chttp
 *
 */

#include "compress/chttp_gzip.h"
#include "dns/chttp_dns.h"
#include "test/chttp_test.h"
#include "tls/chttp_tls.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <time.h>

void
chttp_test_cmd_chttp_test(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_test *test;

	test = chttp_test_convert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);
	chttp_test_ERROR(test->cmds != 1, "test file must begin with chttp_test");

	chttp_test_unescape(&cmd->params[0]);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "%s", cmd->params[0].value);
}

void
chttp_test_cmd_sleep_ms(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	long ms;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 1);

	ms = chttp_test_parse_long(cmd->params[0].value);
	chttp_test_ERROR(ms < 0, "invalid sleep time");

	chttp_test_sleep_ms(ms);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "slept %ldms", ms);
}

void
chttp_test_cmd_connect_or_skip(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	struct chttp_addr addr;
	char *host;
	long port;
	int ret;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	host = cmd->params[0].value;
	port = chttp_test_parse_long(cmd->params[1].value);
	chttp_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	ret = chttp_dns_resolve(&addr, host, strlen(host), port, 0);

	if (ret) {
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "cannot connect to %s:%ld", host, port);
		return;
	}

	ret = chttp_tcp_connect(&addr);

	if (ret) {
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "cannot connect to %s:%ld", host, port);
		return;
	}

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "valid address found %s:%ld", host, port);

	chttp_tcp_close(&addr);

	return;
}

void
chttp_test_cmd_equal(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	int ret;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	chttp_test_ERROR(ret, "not equal '%s' != '%s'", cmd->params[0].value, cmd->params[1].value);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "equal '%s'", cmd->params[0].value);
}

void
chttp_test_cmd_not_equal(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	int ret;

	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 2);

	ret = strcmp(cmd->params[0].value, cmd->params[1].value);

	chttp_test_ERROR(!ret, "equal '%s' == '%s'", cmd->params[0].value, cmd->params[1].value);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "not equal '%s' != '%s'", cmd->params[0].value,
		cmd->params[1].value);
}

void
chttp_test_cmd_tls_or_skip(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (chttp_tls_enabled()) {
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "TLS is supported");
		return;
	} else {
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "TLS not configured");
		return;
	}
}

void
chttp_test_cmd_gzip_or_skip(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	if (chttp_gzip_enabled()) {
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "gzip is supported");
		return;
	} else {
		chttp_test_skip(ctx);
		chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "gzip not configured");
		return;
	}
}

void
chttp_test_cmd_skip(struct chttp_test_context *ctx, struct chttp_test_cmd *cmd)
{
	assert(ctx);
	chttp_test_ERROR_param_count(cmd, 0);

	chttp_test_skip(ctx);

	chttp_test_log(ctx, CHTTP_LOG_VERBOSE, "Skipping");
}
