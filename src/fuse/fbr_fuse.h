/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FUSE_H_INCLUDED_
#define _FBR_FUSE_H_INCLUDED_

#include <errno.h>
#include <pthread.h>

#include "core/fs/fbr_fs.h"

enum fbr_fuse_state {
	FBR_FUSE_NONE = 0,
	FBR_FUSE_MOUNTED
};

struct fbr_fuse_context {
	unsigned int			magic;
#define FBR_FUSE_CTX_MAGIC		0xC07C5CCE

	volatile enum fbr_fuse_state	state;

	char				*path;

	struct fuse_session		*session;
	const struct fuse_lowlevel_ops	*fuse_ops;
	pthread_t			loop_thread;

	struct fbr_fs			fs;
	void				*context_priv;

	unsigned int			error:1;
	unsigned int			debug:1;
	unsigned int			sighandle:1;
	volatile unsigned int		running:1;
	volatile unsigned int		exited:1;

	int				exit_value;
};

struct fuse_conn_info;

extern const struct fuse_lowlevel_ops *FBR_FUSE_OPS;

void fbr_fuse_init(struct fbr_fuse_context *ctx);
void fbr_fuse_free(struct fbr_fuse_context *ctx);
int fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path);
void fbr_fuse_running(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn);
void fbr_fuse_abort(struct fbr_fuse_context *ctx);
void fbr_fuse_unmount(struct fbr_fuse_context *ctx);
void fbr_fuse_error(struct fbr_fuse_context *ctx);

#define fbr_fuse_ctx_ok(ctx)					\
{								\
	assert(ctx);						\
	assert((ctx)->magic == FBR_FUSE_CTX_MAGIC);		\
}
#define fbr_fuse_mounted(ctx)					\
{								\
	fbr_fuse_ctx_ok(ctx);					\
	assert((ctx)->state == FBR_FUSE_MOUNTED);		\
	assert_zero((ctx)->exited);				\
}

#endif /* _FBR_FUSE_H_INCLUDED_ */
