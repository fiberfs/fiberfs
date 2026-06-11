/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_rmdir(struct fbr_request *request, fuse_ino_t parent_inode, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "RMDIR req: %lu parent: %lu name: %s", request->id, parent_inode,
		name);

	struct fbr_directory *parent = fbr_directory_from_inode(fs, parent_inode);
	if (!parent) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, name);

	struct fbr_file *file = fbr_directory_find_file(parent, filename.name, filename.length);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &parent);
		return;
	} else if (!S_ISDIR(file->mode)) {
		fbr_fuse_reply_err(request, ENOTDIR);
		fbr_dindex_release(fs, &parent);
		return;
	}

	struct fbr_fullpath_name dirpath;
	fbr_path_get_full(&file->path, &dirpath);

	struct fbr_directory *directory = fbr_directory_get(fs, &dirpath.path, file->inode);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &parent);
		return;
	} else if (directory->file_count) {
		fbr_fuse_reply_err(request, ENOTEMPTY);
		fbr_dindex_release(fs, &parent);
		fbr_dindex_release(fs, &directory);
		return;
	}

	fbr_fuse_reply_err(request, EIO);

	fbr_dindex_release(fs, &parent);
	fbr_dindex_release(fs, &directory);
}
