/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <stdio.h>

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
		fbr_fuse_reply_err(request, EISDIR);
		return;
	} else if (flags && flags != RENAME_NOREPLACE) {
		fbr_fuse_reply_err(request, EINVAL);
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

	size_t name_len = strlen(name);
	struct fbr_file *file = fbr_directory_find_file(directory, name, name_len);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &directory);
		return;
	} else if (S_ISDIR(file->mode)) {
		fbr_fuse_reply_err(request, EISDIR);
		fbr_dindex_release(fs, &directory);
		return;
	}

	size_t newname_len = strlen(newname);
	struct fbr_file *newfile = fbr_directory_find_file(directory, newname, newname_len);
	if (newfile && S_ISDIR(newfile->mode)) {
		fbr_fuse_reply_err(request, EISDIR);
		fbr_dindex_release(fs, &directory);
		return;
	} else if (newfile && flags & RENAME_NOREPLACE) {
		fbr_fuse_reply_err(request, EEXIST);
		fbr_dindex_release(fs, &directory);
		return;
	}

	enum fbr_flush_flags flush_flags = FBR_FLUSH_RENAME;
	if (flags & RENAME_NOREPLACE) {
		flush_flags |= FBR_FLUSH_RENAME_UNIQUE;
	}

	struct fbr_flush_data flush_data_rename;
	fbr_flush_data_init(&flush_data_rename, file, NULL, NULL, newname, flush_flags, NULL);

	int ret = fbr_fs_flush(fs, &flush_data_rename);
	if (ret) {
		fbr_fuse_reply_err(request, ret);
		fbr_dindex_release(fs, &directory);
		return;
	}

	fbr_inode_t inode = directory->inode;

	fbr_dindex_release(fs, &directory);

	fbr_fuse_reply_err(request, 0);

	if (fbr_request_is_fuse(request)) {
		fbr_fuse_mounted(fs->fuse_ctx);
		assert(fs->fuse_ctx->session);

		fbr_rlog(FBR_LOG_OP_RENAME, "INVAL '%s' inode: %lu (inode)", name, inode);

		ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session, inode, name,
			name_len);
		assert_dev(ret != -ENOSYS);
	}
}
