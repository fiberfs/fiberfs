/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fuse.h"
#include "fbr_fuse_lowlevel.h"

void
fbr_fuse_init(struct fbr_fuse_context *ctx)
{
	assert(ctx);

	fbr_ZERO(ctx);

	ctx->magic = FBR_FUSE_CTX_MAGIC;

	fbr_fuse_ctx_ok(ctx);
}

int
fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path)
{
	struct fuse_args fargs;
	struct fuse_loop_config config;
	char *argv[4];
	int ret;

	fbr_fuse_ctx_ok(ctx);
	assert(ctx->state == FBR_FUSE_NONE);
	assert(path);

	fargs.argv = argv;
	fargs.argv[0] = "fiberfs";
	fargs.argv[1] = "-o";
	fargs.argv[2] = "fsname=fiberfs_test";
	fargs.argv[3] = "-d";
	fargs.argc = sizeof(argv) / sizeof(*argv);
	fargs.allocated = 0;

	if (!ctx->debug) {
		assert(fargs.argc);
		fargs.argc--;
	}

	if (!ctx->fuse_ops) {
		// TODO
		//ctx->fuse_ops = ...
		assert(ctx->fuse_ops);
	}

	ctx->session = fuse_session_new(&fargs, ctx->fuse_ops, sizeof(*ctx->fuse_ops), ctx);

	fuse_opt_free_args(&fargs);

	if (!ctx->session) {
		fbr_fuse_error(ctx, FBR_FUSE_ERROR_MOUNT);
		return 1;
	}

	ctx->state = FBR_FUSE_SESSION;

	ret = fuse_set_signal_handlers(ctx->session);

	if (ret) {
		fbr_fuse_error(ctx, FBR_FUSE_ERROR_MOUNT);
		return 1;
	}

	ctx->state = FBR_FUSE_PREMOUNT;

	ret = fuse_session_mount(ctx->session, path);

	if (ret) {
		fbr_fuse_error(ctx, FBR_FUSE_ERROR_MOUNT);
		return 1;
	}

	ctx->state = FBR_FUSE_MOUNTED;

	fuse_daemonize(ctx->foreground);

	fbr_fuse_mounted(ctx);

	config.max_idle_threads = 16;

	//ctx->exit_value = fuse_session_loop_mt(ctx->session, &config);
	(void)config;

	return 0;
}

void
fbr_fuse_unmount(struct fbr_fuse_context *ctx)
{
	enum fbr_fuse_state state;

	fbr_fuse_ctx_ok(ctx);

	if (ctx->state <= FBR_FUSE_ERROR) {
		return;
	}

	assert(ctx->session);

	state = ctx->state;
	ctx->state = FBR_FUSE_NONE;

	if (!fuse_session_exited(ctx->session)) {
		fuse_session_exit(ctx->session);

		while (!fuse_session_exited(ctx->session)) {
			fbr_sleep_ms(5);
		}
	}

	switch (state) {
		case FBR_FUSE_MOUNTED:
			fuse_session_unmount(ctx->session);
			/* Fallthru */
		case FBR_FUSE_PREMOUNT:
			fuse_remove_signal_handlers(ctx->session);
			/* Fallthru */
		case FBR_FUSE_SESSION:
			fuse_session_destroy(ctx->session);
			ctx->session = NULL;
			break;
		default:
			fbr_ABORT("bad fuse state: %d", state);
	}
}

void
fbr_fuse_error(struct fbr_fuse_context *ctx, enum fbr_fuse_state error)
{
	fbr_fuse_ctx_ok(ctx);
	assert(error <= FBR_FUSE_ERROR && error > FBR_FUSE_NONE);

	fbr_fuse_unmount(ctx);

	ctx->state = error;
	ctx->error = 1;
}
