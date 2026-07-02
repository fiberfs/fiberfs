/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_unlink(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "UNLINK req: %lu parent: %lu name: %s", request->id, parent, name);

	struct fbr_directory *directory = fbr_directory_from_inode(fs, parent);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, name);

	struct fbr_file *file = fbr_directory_find_file(directory, filename.name, filename.length);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &directory);
		return;
	} else if (S_ISDIR(file->mode)) {
		fbr_fuse_reply_err(request, EISDIR);
		fbr_dindex_release(fs, &directory);
		return;
	} else if (file->parent_inode != parent) {
		fbr_fuse_reply_err(request, EACCES);
		fbr_dindex_release(fs, &directory);
		return;
	}

	fbr_inode_add(fs, file);

	fbr_dindex_release(fs, &directory);

	// We delete the file immediately, all previous and existing references are stable
	struct fbr_flush_data flush_data;
	fbr_flush_data_init(&flush_data, file, NULL, NULL, FBR_FLUSH_UNLINK);
	int ret = fbr_fs_flush(fs, &flush_data);

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_err(request, ret);
}
