/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_FUSE_H_INCLUDED_
#define _FBR_FUSE_H_INCLUDED_

#include <errno.h>
#include <pthread.h>

enum fbr_fuse_state {
	FBR_FUSE_NONE = 0,
	FBR_FUSE_MOUNTED
};

struct fbr_fuse_context {
	unsigned int				magic;
#define FBR_FUSE_CTX_MAGIC			0xC07C5CCE

	volatile enum fbr_fuse_state		state;

	char					*path;

	struct fuse_session			*session;
	const struct fbr_fuse_callbacks		*fuse_callbacks;
	pthread_t				loop_thread;
	pthread_mutex_t				mount_lock;

	struct fbr_fs				*fs;
	struct fbr_log				*log;
	struct fbr_cstore			*cstore;

	fbr_bitflag_t				init:1;
	fbr_bitflag_t				debug:1;
	fbr_bitflag_t				signals:1;

	volatile int				running;
	volatile int				exited;
	volatile int				error;

	int					exit_value;
};

struct fuse_conn_info;

extern const struct fuse_lowlevel_ops *FBR_FUSE_OPS;

void fbr_fuse_init(struct fbr_fuse_context *ctx);
int fbr_fuse_has_context(void);
int fbr_fuse_has_error(void);
struct fbr_fuse_context *fbr_fuse_get_context(void);
void fbr_fuse_free(struct fbr_fuse_context *ctx);
int fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path);
void fbr_fuse_running(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn);
void fbr_fuse_unmount(struct fbr_fuse_context *ctx);
void fbr_fuse_unmount_signal(void);

void fbr_fuse_LOCK(struct fbr_fuse_context *fuse_ctx, pthread_mutex_t *lock);

#define fbr_fuse_context_ok(ctx)				\
	fbr_magic_check(ctx, FBR_FUSE_CTX_MAGIC)
#define fbr_fuse_mounted(ctx)					\
{								\
	fbr_fuse_context_ok(ctx);				\
	assert((ctx)->state == FBR_FUSE_MOUNTED);		\
	assert_zero((ctx)->exited);				\
	assert_zero((ctx)->error);				\
}

#endif /* _FBR_FUSE_H_INCLUDED_ */
