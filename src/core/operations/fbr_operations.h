/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_OPERATIONS_H_INCLUDED_
#define _FBR_OPERATIONS_H_INCLUDED_

#include "core/request/fbr_request.h"

void fbr_ops_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name);
void fbr_ops_mkdir(struct fbr_request *request, fuse_ino_t parent, const char *name, mode_t mode);
void fbr_ops_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
	struct fuse_file_info *fi);
void fbr_ops_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_create(struct fbr_request *request, fuse_ino_t parent, const char *name, mode_t mode,
	struct fuse_file_info *fi);
void fbr_ops_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
	struct fuse_file_info *fi);
void fbr_ops_write(struct fbr_request *request, fuse_ino_t ino, const char *buf, size_t size,
	off_t off, struct fuse_file_info *fi);
void fbr_ops_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_fsync(struct fbr_request *request, fuse_ino_t ino, int datasync,
	struct fuse_file_info *fi);
void fbr_ops_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup);
void fbr_ops_forget_multi(struct fbr_request *request, size_t count,
	struct fuse_forget_data *forgets);

#endif /* _FBR_OPERATIONS_H_INCLUDED_ */
