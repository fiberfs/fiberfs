/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_rename(struct fbr_request *request, fuse_ino_t parent, const char *name,
    fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "RENAME req: %lu parent: %lu name: '%s' newparent: %lu newname: '%s'"
		" flags: %d", request->id, parent, name, newparent, newname, flags);

	if (parent != newparent) {
		fbr_rlog(FBR_LOG_OP_RENAME, "parent directories must match");
		fbr_fuse_reply_err(request, EFAULT);
		return;
	}

	int error = fbr_check_name(newname);
	if (error) {
		fbr_fuse_reply_err(request, error);
		return;
	}

	struct fbr_directory *directory = fbr_directory_from_inode(fs, parent);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	struct fbr_file *file = fbr_directory_find_file(directory, name, strlen(name));
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &directory);
		return;
	}

	// TODO check newname

	struct fbr_flush_data flush_data_rename;
	fbr_flush_data_init(&flush_data_rename, file, NULL, NULL, name, FBR_FLUSH_RENAME);

	int ret = fbr_fs_flush(fs, &flush_data_rename);
	if (ret) {
		fbr_fuse_reply_err(request, ret);
		fbr_dindex_release(fs, &directory);
		return;
	}

	fbr_dindex_release(fs, &directory);

	fbr_fuse_reply_err(request, 0);
}
