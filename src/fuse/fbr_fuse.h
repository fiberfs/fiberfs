/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FUSE_H_INCLUDED_
#define _FBR_FUSE_H_INCLUDED_

#include <errno.h>
#include <pthread.h>

#include "fiberfs.h"

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

	void				*priv;

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
struct fbr_fuse_context *fbr_fuse_get_ctx(void);
void fbr_fuse_running(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn);
void fbr_fuse_abort(struct fbr_fuse_context *ctx);
void fbr_fuse_unmount(struct fbr_fuse_context *ctx);
void fbr_fuse_error(struct fbr_fuse_context *ctx);
void __fbr_attr_printf_p(7) fbr_fuse_do_assert(int cond, void *req, const char *assertion,
	const char *function, const char *file, int line, const char *fmt, ...);

#define fbr_fuse_ctx_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert((ctx)->magic == FBR_FUSE_CTX_MAGIC);		\
	} while (0)
#define fbr_fuse_mounted(ctx)						\
	do {								\
		fbr_fuse_ctx_ok(ctx);					\
		assert((ctx)->state == FBR_FUSE_MOUNTED);		\
		assert_zero((ctx)->exited);				\
	} while (0)
#define fbr_fuse_ASSERT(cond, req)					\
	fbr_fuse_do_assert(cond, req, #cond, __func__, __FILE__,	\
		__LINE__, NULL);
#define fbr_fuse_ASSERTF(cond, req, fmt, ...)				\
	fbr_fuse_do_assert(cond, req, #cond, __func__, __FILE__,	\
		__LINE__, fmt,	##__VA_ARGS__);

#endif /* _FBR_FUSE_H_INCLUDED_ */
