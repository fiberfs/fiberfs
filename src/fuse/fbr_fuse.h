/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FUSE_H_INCLUDED_
#define _FBR_FUSE_H_INCLUDED_

enum fbr_fuse_state {
	FBR_FUSE_NONE = 0,
	FBR_FUSE_ERROR_MOUNT,
	FBR_FUSE_ERROR,
	FBR_FUSE_SESSION,
	FBR_FUSE_PREMOUNT,
	FBR_FUSE_MOUNTED
};

struct fbr_fuse_context {
	unsigned int			magic;
#define FBR_FUSE_CTX_MAGIC		0xC07C5CCE

	enum fbr_fuse_state		state;

	struct fuse_session		*session;
	const struct fuse_lowlevel_ops	*fuse_ops;

	unsigned int			error:1;
	unsigned int			debug:1;
	unsigned int			foreground:1;

	int				exit_value;
};

void fbr_fuse_init(struct fbr_fuse_context *ctx);
int fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path);
void fbr_fuse_unmount(struct fbr_fuse_context *ctx);
void fbr_fuse_error(struct fbr_fuse_context *ctx, enum fbr_fuse_state error);

#define fbr_fuse_ctx_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert((ctx)->magic == FBR_FUSE_CTX_MAGIC);		\
	} while (0)
#define fbr_fuse_mounted(ctx)						\
	do {								\
		fbr_fuse_ctx_ok(ctx);					\
		assert((ctx)->state == FBR_FUSE_MOUNTED);		\
	} while (0)

#endif /* _FBR_FUSE_H_INCLUDED_ */
