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

#define _CONFIG_THREADS		4

static void *
_config_thread(void *arg)
{
	assert_zero(arg);

	struct chttp_context chttp;

	while (CHTTP_CONFIG.updates == 3) {
		chttp_context_init(&chttp);
		chttp_context_free(&chttp);
	}

	return NULL;
}

void
chttp_test_cmd_chttp_config_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** startup");
	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert_zero(CHTTP_CONFIG.init);
	assert_zero(CHTTP_CONFIG.updates);
	assert_zero(CHTTP_CONFIG.attempts);

	struct chttp_context chttp;
	chttp_context_init(&chttp);

	fbr_test_logs("*** init");
	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert(CHTTP_CONFIG.init);
	assert(CHTTP_CONFIG.updates == 1);
	assert(CHTTP_CONFIG.attempts == 1);
	assert_zero(CHTTP_CONFIG.update_interval);

	CHTTP_CONFIG.update_interval = 1;

	chttp_context_reset(&chttp);

	fbr_test_logs("*** reset");
	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert(CHTTP_CONFIG.updates == 1);
	assert(CHTTP_CONFIG.attempts == 1);

	fbr_test_sleep_ms(1020);

	chttp_context_free(&chttp);
	chttp_context_init(&chttp);

	fbr_test_logs("*** init 1s");
	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert(CHTTP_CONFIG.updates == 2);
	assert(CHTTP_CONFIG.attempts == 2);

	chttp_context_free(&chttp);
	chttp_context_init(&chttp);

	fbr_test_logs("*** init 1s again");
	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert(CHTTP_CONFIG.updates == 2);
	assert(CHTTP_CONFIG.attempts == 3);

	fbr_test_sleep_ms(1020);

	chttp_context_free(&chttp);
	chttp_context_init(&chttp);
	chttp_context_free(&chttp);

	fbr_test_logs("*** init 2s");
	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert(CHTTP_CONFIG.updates == 3);
	assert(CHTTP_CONFIG.attempts == 4);

	pthread_t threads[_CONFIG_THREADS];
	assert(fbr_array_len(threads) > 0);

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _config_thread, NULL));
	}

	fbr_test_logs("*** threads created: %zu", fbr_array_len(threads));

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}

	fbr_test_logs("*** all threads joined");

	fbr_test_logs("CHTTP_CONFIG.updates=%lu", CHTTP_CONFIG.updates);
	fbr_test_logs("CHTTP_CONFIG.attempts=%lu", CHTTP_CONFIG.attempts);

	assert(CHTTP_CONFIG.updates == 4);

	fbr_test_logs("chttp_config_test passed");
}
