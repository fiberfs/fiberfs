/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_OPERATIONS_H_INCLUDED_
#define _FBR_OPERATIONS_H_INCLUDED_

#include "core/request/fbr_request.h"

void fbr_ops_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name);
void fbr_ops_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);
void fbr_ops_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
	struct fuse_file_info *fi);
void fbr_ops_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi);

#endif /* _FBR_OPERATIONS_H_INCLUDED_ */
