/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>

#include "test/fbr_test.h"

static void
_test_error_CRASH(void)
{
	int *i = (int*)1;
	i--;
	*i = 1;
}

void
fbr_test_cmd_test_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_ABORT("test_error cmd");
}

static void *
_test_thread_error(void *arg)
{
	(void)arg;
	fbr_test_ABORT("test_thread_error cmd");
	return NULL;
}

void
fbr_test_cmd_test_thread_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	pthread_t thread;
	pt_assert(pthread_create(&thread, NULL, _test_thread_error, NULL));
	pt_assert(pthread_join(thread, NULL));
}

void
fbr_test_cmd_test_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_error_CRASH();
}

static void *
_test_thread_crash(void *arg)
{
	(void)arg;
	_test_error_CRASH();
	return NULL;
}

void
fbr_test_cmd_test_thread_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	pthread_t thread;
	pt_assert(pthread_create(&thread, NULL, _test_thread_crash, NULL));
	pt_assert(pthread_join(thread, NULL));
}

void
fbr_test_cmd_test_fork_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (fbr_test_can_fork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	fbr_test_ABORT("test_fork_error cmd");
}

void
fbr_test_cmd_test_fork_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (fbr_test_can_fork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	_test_error_CRASH();
}
