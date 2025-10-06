/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "test/fbr_test.h"

struct fbr_test_shell {
	unsigned int				magic;
#define _SHELL_MAGIC				0x80CD260D

	size_t					thread_count;
	pthread_t				*threads;
};

static void
_shell_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_magic_check(ctx->shell, _SHELL_MAGIC);

	fbr_finish_ERROR(ctx->shell->thread_count, "shell_bg commands running");

	free(ctx->shell->threads);

	fbr_zero(ctx->shell);
	free(ctx->shell);

	ctx->shell = NULL;
}

static void
_shell_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (!ctx->shell) {
		struct fbr_test_shell *shell = calloc(1, sizeof(*shell));
		assert(shell);

		shell->magic = _SHELL_MAGIC;

		ctx->shell = shell;

		fbr_test_register_finish(ctx, "shell", _shell_finish);
	}

	fbr_magic_check(ctx->shell, _SHELL_MAGIC);
}

void
fbr_cmd_shell(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "shell cmd: '%s'", cmd->params[0].value);

	int ret = system(cmd->params[0].value);

	fbr_test_ASSERT(WIFEXITED(ret), "shell cmd failed");
	fbr_test_ERROR(WEXITSTATUS(ret), "shell cmd returned an error");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "shell cmd passed");
}

void
fbr_cmd_skip_shell_failure(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "skip_shell cmd: '%s'", cmd->params[0].value);

	int ret = system(cmd->params[0].value);

	if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "skip_shell cmd failed");
	} else {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "skip_shell cmd passed");
	}
}

static void *
_test_shell_bg(void *arg)
{
	char *shell_cmd = (char*)arg;

	fbr_test_logs("shell_bg cmd: '%s'", shell_cmd);

	int ret = system(shell_cmd);

	free(shell_cmd);

	int *error = malloc(sizeof(*error));
	assert(error);

	*error = 0;

	if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
		*error = 1;
	}

	return (void*)error;
}

void
fbr_cmd_shell_bg(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_shell_init(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	ctx->shell->thread_count++;
	fbr_test_ERROR(ctx->shell->thread_count > 1000, "Too many shell_bg calls");

	ctx->shell->threads = realloc(ctx->shell->threads,
		ctx->shell->thread_count * sizeof(*ctx->shell->threads));

	char *shell_cmd = strdup(cmd->params[0].value);
	assert(shell_cmd);

	pt_assert(pthread_create(&ctx->shell->threads[ctx->shell->thread_count - 1], NULL,
		_test_shell_bg, shell_cmd));
}

static int
_test_shell_waitall(struct fbr_test_shell *shell)
{
	fbr_magic_check(shell, _SHELL_MAGIC);

	int error = 0;

	for (size_t i = 0; i < shell->thread_count; i++) {
		int *ret;
		pt_assert(pthread_join(shell->threads[i], (void**)&ret));

		assert(ret);

		if (*ret) {
			error = 1;
			fbr_test_warn(error, "shell_bg %zu returned error", i + 1);
		} else {
			fbr_test_logs("shell_bg %zu passed", i + 1);
		}

		free(ret);
	}

	shell->thread_count = 0;

	return error;
}

void
fbr_cmd_shell_waitall(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_shell_init(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	int shell_error = _test_shell_waitall(ctx->shell);
	fbr_test_ERROR(shell_error, "shell_bg error detected");
}
