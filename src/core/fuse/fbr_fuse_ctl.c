/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
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
#include "core/fs/fbr_fs.h"
#include "cstore/fbr_cstore_api.h"
#include "log/fbr_log.h"

struct fbr_fuse_context *_FUSE_CTX;

void
fbr_fuse_init(struct fbr_fuse_context *ctx)
{
	assert(ctx);

	fbr_ZERO(ctx);
	ctx->magic = FBR_FUSE_CTX_MAGIC;
	ctx->init = 1;

	pt_assert(pthread_mutex_init(&ctx->mount_lock, NULL));

	fbr_fuse_context_ok(ctx);
}

int
fbr_fuse_has_context(void)
{
	if (_FUSE_CTX) {
		return 1;
	}

	return 0;
}

int
fbr_fuse_has_error(void)
{
	if (_FUSE_CTX) {
		fbr_fuse_context_ok(_FUSE_CTX);
		if (_FUSE_CTX->error) {
			return 1;
		}
	}

	return 0;
}

struct fbr_fuse_context *
fbr_fuse_get_context(void)
{
	fbr_fuse_context_ok(_FUSE_CTX);
	return _FUSE_CTX;
}

static void
_fuse_error(struct fbr_fuse_context *ctx)
{
	assert_dev(ctx);

	fbr_fuse_unmount(ctx);
	assert_dev(ctx->state == FBR_FUSE_NONE);

	ctx->error = 1;
}

static void *
_fuse_mount_thread(void *arg)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)arg;
	fbr_fuse_mounted(ctx);
	assert(ctx->session);
	assert_zero(ctx->running);

	fbr_thread_name("fbr_fuse_sess");

	struct fuse_loop_config config;
	fbr_ZERO(&config);
	config.max_idle_threads = 16;

	ctx->exit_value = fuse_session_loop_mt(ctx->session, &config);

	fbr_rlog(FBR_LOG_FUSE, "session exit");

	ctx->exited = 1;

	fuse_session_unmount(ctx->session);

	return NULL;
}

int
fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path)
{
	fbr_fuse_context_ok(ctx);
	assert(ctx->state == FBR_FUSE_NONE);

	pt_assert(pthread_mutex_lock(&ctx->mount_lock));

	fbr_fuse_context_ok(ctx);
	assert(ctx->state == FBR_FUSE_NONE);
	assert_zero(ctx->session);
	assert(ctx->fuse_callbacks);
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
	fargs.argc = fbr_array_len(argv);
	assert(fargs.argc == 6);
	fargs.allocated = 0;

	if (!ctx->debug) {
		assert(fargs.argc);
		fargs.argc--;
	}

	ctx->session = fuse_session_new(&fargs, FBR_FUSE_OPS, sizeof(*FBR_FUSE_OPS), ctx);

	fuse_opt_free_args(&fargs);

	if (!ctx->session) {
		pt_assert(pthread_mutex_unlock(&ctx->mount_lock));
		_fuse_error(ctx);
		return 1;
	}

	int ret = fuse_set_signal_handlers(ctx->session);
	if (!ret) {
		ctx->signals = 1;
	}

	ctx->path = strdup(path);
	assert(ctx->path);

	ret = fuse_session_mount(ctx->session, path);

	if (ret) {
		pt_assert(pthread_mutex_unlock(&ctx->mount_lock));
		_fuse_error(ctx);
		return 1;
	}

	ctx->state = FBR_FUSE_MOUNTED;

	ctx->log = fbr_log_alloc(ctx->path, fbr_log_default_size());
	fbr_log_ok(ctx->log);

	ctx->fs = fbr_fs_alloc();
	fbr_fs_ok(ctx->fs);

	ctx->fs->fuse_ctx = ctx;

	assert_zero(_FUSE_CTX);
	_FUSE_CTX = ctx;

	fbr_rlog(FBR_LOG_FUSE, "initialized");

	pt_assert(pthread_create(&ctx->loop_thread, NULL, _fuse_mount_thread, ctx));

	while (!ctx->running) {
		fbr_sleep_ms(5);
		fbr_fuse_context_ok(ctx);

		if (ctx->error) {
			pt_assert(pthread_mutex_unlock(&ctx->mount_lock));
			fbr_rlog(FBR_LOG_ERROR, "session mount error");
			return 1;
		} else if (ctx->exited) {
			pt_assert(pthread_mutex_unlock(&ctx->mount_lock));
			_fuse_error(ctx);
			fbr_rlog(FBR_LOG_ERROR, "session mount exit error");
			return 1;
		}
	}

	pt_assert(pthread_mutex_unlock(&ctx->mount_lock));

	fbr_rlog(FBR_LOG_FUSE, "session mounted");

	return 0;
}

void
fbr_fuse_running(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);

	ctx->running = 1;
}

static void
_fuse_abort(struct fbr_fuse_context *ctx)
{
	assert_dev(ctx);
	assert_dev(ctx->state == FBR_FUSE_MOUNTED);
	assert_dev(ctx->session);

	if (ctx->exited) {
		return;
	}

	fuse_session_exit(ctx->session);

	char cmd[FBR_PATH_MAX + 32];
	size_t len = snprintf(cmd, sizeof(cmd), "fusermount -u %s%s",
		ctx->path, ctx->debug ? "" : " >/dev/null 2>&1");
	assert(len < sizeof(cmd));

	int ret = system(cmd);
	(void)ret;
}

void
fbr_fuse_unmount(struct fbr_fuse_context *ctx)
{
	fbr_fuse_context_ok(ctx);

	pt_assert(pthread_mutex_lock(&ctx->mount_lock));
	fbr_fuse_context_ok(ctx);

	if (ctx->state != FBR_FUSE_MOUNTED) {
		pt_assert(pthread_mutex_unlock(&ctx->mount_lock));
		return;
	}

	fbr_rlog(FBR_LOG_FUSE, "unmount starting");

	_fuse_abort(ctx);
	fbr_request_pool_shutdown(ctx->fs);

	assert_dev(ctx->session);

	if (ctx->running) {
		pt_assert(pthread_join(ctx->loop_thread, NULL));
		assert(ctx->exited);
	} else {
		ctx->error = 1;

		if (!ctx->exited) {
			fuse_session_unmount(ctx->session);
		}
	}

	if (ctx->signals) {
		fuse_remove_signal_handlers(ctx->session);
		ctx->signals = 0;
	}

	ctx->state = FBR_FUSE_NONE;

	fbr_rlog(FBR_LOG_FUSE, "umount complete");
	// TODO we need to push some kind of special log message to bounce log readers

	pt_assert(pthread_mutex_unlock(&ctx->mount_lock));

	fbr_fs_free(ctx->fs);
	ctx->fs = NULL;
}

void
fbr_fuse_unmount_signal(void)
{
	if (_FUSE_CTX) {
		fbr_fuse_context_ok(_FUSE_CTX);
		_FUSE_CTX->error = 1;

		fbr_fuse_unmount(_FUSE_CTX);
	}
}

void
fbr_fuse_free(struct fbr_fuse_context *ctx)
{
	fbr_fuse_context_ok(ctx);
	assert(ctx->state == FBR_FUSE_NONE);

	_FUSE_CTX = NULL;

	if (ctx->session) {
		fuse_session_destroy(ctx->session);
	}

	if (ctx->cstore) {
		fbr_cstore_free(ctx->cstore);
	}

	if (ctx->path) {
		free(ctx->path);
	}

	if (ctx->log) {
		fbr_log_free(ctx->log);
	}

	pt_assert(pthread_mutex_destroy(&ctx->mount_lock));

	fbr_ZERO(ctx);
}
