/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_FUSE_CALLBACK_H_INCLUDED_
#define _FBR_FUSE_CALLBACK_H_INCLUDED_

#include "fiberfs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

struct fbr_request {
	unsigned int				magic;
#define FBR_REQUEST_MAGIC			0xE2719F6A

	fuse_req_t				fuse_req;
	struct fbr_fuse_context			*fuse_ctx;
};

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
	void (*write_buf)(struct fbr_request *request, fuse_ino_t ino, struct fuse_bufvec *bufv,
		off_t off, struct fuse_file_info *fi);
	void (*write) (struct fbr_request *request, fuse_ino_t ino, const char *buf,
		size_t size, off_t off, struct fuse_file_info *fi);
	void (*flush)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*release)(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
	void (*fsync) (struct fbr_request *request, fuse_ino_t ino, int datasync,
		struct fuse_file_info *fi);
	void (*forget)(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup);
	void (*forget_multi) (struct fbr_request *request, size_t count,
		struct fuse_forget_data *forgets);
};

void fbr_context_request_init(void);
void fbr_context_request_finish(void);

struct fbr_fuse_context *fbr_fuse_callback_ctx(void);

struct fbr_request *fbr_request_alloc(fuse_req_t fuse_req);
struct fbr_request *fbr_request_get(void);
void fbr_request_free(struct fbr_request *request);

void fbr_fuse_reply_none(struct fbr_request *request);
void fbr_fuse_reply_err(struct fbr_request *request, int error);
void fbr_fuse_reply_buf(struct fbr_request *request, const char *buf, size_t size);
void fbr_fuse_reply_iov(struct fbr_request *request, const struct iovec *iov, int count);
void fbr_fuse_reply_data(struct fbr_request *request, struct fuse_bufvec *bufv,
	enum fuse_buf_copy_flags flags);
void fbr_fuse_reply_entry(struct fbr_request *request, const struct fuse_entry_param *entry);
void fbr_fuse_reply_attr(struct fbr_request *request, const struct stat *attr,
	double attr_timeout);
void fbr_fuse_reply_open(struct fbr_request *request, const struct fuse_file_info *fi);
void fbr_fuse_reply_write(struct fbr_request *request, size_t count);

#define fbr_request_ok(request)						\
{									\
	assert(request);						\
	assert((request)->magic == FBR_REQUEST_MAGIC);			\
}
#define fbr_request_valid(request)					\
{									\
	fbr_request_ok(request);					\
	fbr_fuse_mounted(request->fuse_ctx);				\
}

#endif /* _FBR_FUSE_CALLBACK_H_INCLUDED_ */
