/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FUSE_H_INCLUDED_
#define _FBR_FUSE_H_INCLUDED_

enum fbr_fuse_state {
	FBR_FUSE_UNDEF = 0,
	FBR_FUSE_INIT,
	FBR_FUSE_PREMOUNT,
	FBR_FUSE_MOUNTED,
	FBR_FUSE_ERROR
};

struct fbr_fuse_context {
	unsigned int			magic;
#define FBR_FUSE_CTX_MAGIC		0xC07C5CCE

	enum fbr_fuse_state		state;

	struct fuse_session		*session;
	const struct fuse_lowlevel_ops	*fuse_ops;

	unsigned int			debug:1;
};

void fbr_fuse_init(struct fbr_fuse_context *ctx);
int fbr_fuse_mount(struct fbr_fuse_context *ctx, const char *path);
void fbr_fuse_unmount(struct fbr_fuse_context *ctx);

#define fbr_fuse_ctx_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert((ctx)->magic == FBR_FUSE_CTX_MAGIC);		\
	} while (0)

#endif /* _FBR_FUSE_H_INCLUDED_ */
