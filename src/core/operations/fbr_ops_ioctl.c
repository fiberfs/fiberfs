/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_ioctl(struct fbr_request *request, fuse_ino_t ino, unsigned int cmd, void *arg,
    struct fuse_file_info *fi, unsigned flags, const void *in_buf, size_t in_bufsz,
    size_t out_bufsz)
{
	assert_zero(fbr_is_flag(flags, FUSE_IOCTL_UNRESTRICTED));
	(void)arg;
	(void)fi;
	(void)in_buf;

	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "IOCTL req: %lu ino: %lu cmd: %u in_bufsz: %zu out_bufsz: %zu",
		request->id, ino, cmd, in_bufsz, out_bufsz);

	struct fbr_file *file = fbr_inode_take_alias(fs, ino);
	if (!file || fbr_file_is_file(file) || !fbr_is_flag(flags, FUSE_IOCTL_DIR)) {
		fbr_fuse_reply_err(request, ENOTTY);
		return;
	}

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_err(request, EINVAL);
}
