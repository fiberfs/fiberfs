/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(fs->store);

	fbr_rlog(FBR_LOG_OP, "LOOKUP req: %lu parent: %lu name: '%s'", request->id, parent, name);

	struct fbr_directory *directory = fbr_directory_from_inode(fs, parent);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	struct fbr_path_name dirpath;
	fbr_path_shared_name(directory->path, &dirpath);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, name);

	int error = fbr_check_name(&dirpath, &filename);
	if (error) {
		fbr_fuse_reply_err(request, error);
		return;
	}

	struct fbr_file *file = fbr_directory_find_file(directory, filename.name, filename.length);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &directory);
		return;
	} else if (file->parent_inode != parent) {
		fbr_fuse_reply_err(request, EACCES);
		fbr_dindex_release(fs, &directory);
		return;
	} else if (file->state == FBR_FILE_DELETED) {
		fbr_fuse_reply_err(request, ENOENT);
		fbr_dindex_release(fs, &directory);
		return;
	}

	struct fbr_fullpath_name path;
	const char *fullname = fbr_path_get_full(&file->path, &path);
	fbr_rlog(FBR_LOG_OP_LOOKUP, "found file: '%s' (inode: %lu)", fullname, file->inode);

	if (fbr_is_dev()) {
		struct fbr_path_name _filename;
		fbr_path_get_file(&file->path, &_filename);
		assert(_filename.length == filename.length);
		assert_zero(strcmp(name, _filename.name));
	}

	struct fuse_entry_param entry;
	fbr_zero(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(fs, file, &entry.attr);

	if (fbr_request_is_fuse(request)) {
		fbr_inode_add(fs, file);
	}

	fbr_fuse_reply_entry(request, &entry);

	fbr_dindex_release(fs, &directory);
}
