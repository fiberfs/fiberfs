/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fi;

	fbr_rlog(FBR_LOG_OP, "ATTR req: %lu ino: %lu", request->id, ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	struct stat st;
	fbr_file_attr(fs, file, &st);

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_attr(request, &st, fbr_fs_dentry_ttl(fs));
}
