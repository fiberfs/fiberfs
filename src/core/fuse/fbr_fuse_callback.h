/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FUSE_CALLBACK_H_INCLUDED_
#define _FBR_FUSE_CALLBACK_H_INCLUDED_

#include "fiberfs.h"
#include "fbr_fuse_lowlevel.h"
#include "core/context/fbr_request.h"

struct fbr_fuse_callbacks {
	void (*init)(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn);
	void (*destroy)(struct fbr_fuse_context *ctx);
	void (*lookup)(struct fbr_request *request, fuse_ino_t parent, const char *name);
	void (*getattr)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*opendir)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*readdir)(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
		struct fuse_file_info *fi);
	void (*releasedir)(struct fbr_request *request, fuse_ino_t ino,
		struct fuse_file_info *fi);
	void (*open)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*read)(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
		struct fuse_file_info *fi);
	void (*flush)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*release)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*forget)(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup);
	void (*forget_multi) (struct fbr_request *request, size_t count,
		struct fuse_forget_data *forgets);
};

struct fbr_fuse_context *fbr_fuse_get_ctx(fuse_req_t req);
void fbr_fuse_reply_none(struct fbr_request *request);
void fbr_fuse_reply_err(struct fbr_request *request, int error);
void fbr_fuse_reply_buf(struct fbr_request *request, const char *buf, size_t size);
void fbr_fuse_reply_entry(struct fbr_request *request, const struct fuse_entry_param *entry);
void fbr_fuse_reply_attr(struct fbr_request *request, const struct stat *attr,
	double attr_timeout);
void fbr_fuse_reply_open(struct fbr_request *request, const struct fuse_file_info *fi);

// TODO this all goes away
void __fbr_attr_printf(6) fbr_fuse_do_abort(fuse_req_t req, const char *assertion,
	const char *function, const char *file, int line, const char *fmt, ...);

#define fbr_fuse_ASSERTF(cond, req, fmt, ...)					\
{										\
	if (__builtin_expect(!(cond), 0)) {					\
		fbr_fuse_do_abort(req, #cond, __func__, __FILE__, 	\
			__LINE__, fmt, ##__VA_ARGS__);				\
	}									\
}
#define fbr_fuse_ASSERT(cond, req)						\
	fbr_fuse_ASSERTF(cond, req, NULL)

#endif /* _FBR_FUSE_CALLBACK_H_INCLUDED_ */
