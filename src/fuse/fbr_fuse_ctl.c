/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_lowlevel.h"
#include "core/fbr_core_fs.h"

extern struct fbr_fuse_context *_FUSE_CTX;

void
fbr_fuse_init(struct fbr_fuse_context *ctx)
{
	assert(ctx);

	fbr_ZERO(ctx);
	ctx->magic = FBR_FUSE_CTX_MAGIC;

	fbr_core_fs_init(&ctx->fs);

	fbr_fuse_ctx_ok(ctx);
}

static void *
_fuse_mount_thread(void *arg)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)arg;
	fbr_fuse_mounted(ctx);
	assert(ctx->session);
	assert_zero(ctx->running);

	struct fuse_loop_config config;
	fbr_ZERO(&config);
	config.max_idle_threads = 16;

	ctx->exit_value = fuse_session_loop_mt(ctx->session, &config);

	ctx->exited = 1;

	fuse_session_unmount(ctx->session);

	return NULL;
}

int
fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path)
{
	fbr_fuse_ctx_ok(ctx);
	assert(ctx->state == FBR_FUSE_NONE);
	assert_zero(ctx->session);
	assert(ctx->fuse_ops);
	assert(path);

	char *argv[6];
	struct fuse_args fargs;
	fargs.argv = argv;
	// TODO allow_other?
	fargs.argv[0] = "fiberfs";
	fargs.argv[1] = "-o";
	fargs.argv[2] = "fsname=fiberfs";
	fargs.argv[3] = "-o";
	fargs.argv[4] = "default_permissions";
	fargs.argv[5] = "-d";
	fargs.argc = sizeof(argv) / sizeof(*argv);
	assert(fargs.argc == 6);
	fargs.allocated = 0;

	if (!ctx->debug) {
		assert(fargs.argc);
		fargs.argc--;
	}

	ctx->session = fuse_session_new(&fargs, FBR_FUSE_OPS, sizeof(*FBR_FUSE_OPS), ctx);

	fuse_opt_free_args(&fargs);

	if (!ctx->session) {
		fbr_fuse_error(ctx);
		return 1;
	}

	int ret;

	if (ctx->sighandle) {
		ret = fuse_set_signal_handlers(ctx->session);

		if (ret) {
			ctx->sighandle = 0;
		}
	}

	ctx->path = strdup(path);
	assert(ctx->path);

	ret = fuse_session_mount(ctx->session, path);

	if (ret) {
		fbr_fuse_error(ctx);
		return 1;
	}

	ctx->state = FBR_FUSE_MOUNTED;

	assert_zero(_FUSE_CTX);
	_FUSE_CTX = ctx;

	assert_zero(pthread_create(&ctx->loop_thread, NULL, _fuse_mount_thread, ctx));

	while (!ctx->running) {
		fbr_sleep_ms(5);

		if (ctx->exited) {
			fbr_fuse_error(ctx);
			return 1;
		}
	}

	return 0;
}

void
fbr_fuse_running(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);

	ctx->running = 1;
}

void
fbr_fuse_error(struct fbr_fuse_context *ctx)
{
	fbr_fuse_ctx_ok(ctx);

	fbr_fuse_unmount(ctx);

	assert(ctx->state == FBR_FUSE_NONE);

	ctx->error = 1;
}

void
fbr_fuse_abort(struct fbr_fuse_context *ctx)
{
	fbr_fuse_ctx_ok(ctx);

	if (ctx->state != FBR_FUSE_MOUNTED || ctx->exited) {
		return;
	}

	fuse_session_exit(ctx->session);

	char cmd[PATH_MAX + 32];
	size_t len = snprintf(cmd, sizeof(cmd), "fusermount -u %s%s",
		ctx->path, ctx->debug ? "" : " >/dev/null 2>&1");
	assert(len < sizeof(cmd));

	int ret = system(cmd);
	(void)ret;
}

void
fbr_fuse_unmount(struct fbr_fuse_context *ctx)
{
	fbr_fuse_ctx_ok(ctx);

	if (ctx->state == FBR_FUSE_NONE) {
		return;
	}

	fbr_fuse_abort(ctx);

	assert_zero(pthread_join(ctx->loop_thread, NULL));
	assert(ctx->exited);
	assert(ctx->session);

	_FUSE_CTX = NULL;

	if (ctx->sighandle) {
		fuse_remove_signal_handlers(ctx->session);
	}

	ctx->state = FBR_FUSE_NONE;

	fbr_core_fs_free(&ctx->fs);
}

void
fbr_fuse_free(struct fbr_fuse_context *ctx)
{
	fbr_fuse_ctx_ok(ctx);
	assert(ctx->state == FBR_FUSE_NONE);
	assert_zero(_FUSE_CTX);

	if (ctx->running) {
		assert(ctx->exited);
	}

	if (ctx->session) {
		fuse_session_destroy(ctx->session);
		ctx->session = NULL;
	}

	if (ctx->path) {
		free(ctx->path);
		ctx->path = NULL;
	}

	fbr_ZERO(ctx);
}
