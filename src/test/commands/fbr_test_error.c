/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <unistd.h>

#include "test/fbr_test.h"

static void
_test_error_CRASH(void)
{
	int *i = (int*)1;
	i--;
	*i = 1;
}

void
fbr_cmd_test_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
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
fbr_cmd_test_thread_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	pthread_t thread;
	pt_assert(pthread_create(&thread, NULL, _test_thread_error, NULL));
	pt_assert(pthread_join(thread, NULL));
}

void
fbr_cmd_test_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
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
fbr_cmd_test_thread_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	pthread_t thread;
	pt_assert(pthread_create(&thread, NULL, _test_thread_crash, NULL));
	pt_assert(pthread_join(thread, NULL));
}

void
fbr_cmd_test_fork_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
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
fbr_cmd_test_fork_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (fbr_test_can_fork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	_test_error_CRASH();
}

static void
_error_finish_crash(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	_test_error_CRASH();
}

void
fbr_cmd_test_finish_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_register_finish(ctx, "test_crash_finish", _error_finish_crash);
}

void
fbr_cmd_test_double_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_register_finish(ctx, "test_crash_finish", _error_finish_crash);

	_test_error_CRASH();
}

void
fbr_cmd_test_triple_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_register_finish(ctx, "test_crash_finish", _error_finish_crash);

	// Kernel doesnt allow nested signals
	// So this thread starts with an error since it can trigger the finish crash
	pthread_t thread;
	pt_assert(pthread_create(&thread, NULL, _test_thread_error, NULL));

	// This thread always exits
	_test_error_CRASH();
}

void
fbr_cmd__exit(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_exit(1);
}
