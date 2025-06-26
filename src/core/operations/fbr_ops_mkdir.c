/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_mkdir(struct fbr_request *request, fuse_ino_t parent, const char *name, mode_t mode)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(fs->store);

	fs->log("MKDIR req: %lu parent: %lu name: %s mode: %u", request->id, parent, name,
		mode);

	struct fbr_file *parent_file = fbr_inode_take(fs, parent);

	if (!parent_file || parent_file->state == FBR_FILE_EXPIRED) {
		fbr_fuse_reply_err(request, ENOTDIR);

		if (parent_file) {
			fbr_inode_release(fs, &parent_file);
		}

		return;
	}

	struct fbr_path_name parent_dirname;
	char buf[PATH_MAX];
	fbr_path_get_full(&parent_file->path, &parent_dirname, buf, sizeof(buf));

	fs->log("MKDIR found parent_file: '%s' (inode: %lu)", parent_dirname.name,
		parent_file->inode);

	struct fbr_directory *directory = fbr_dindex_take(fs, &parent_dirname, 0);

	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);

		fbr_inode_release(fs, &parent_file);
		return;
	}

	fbr_directory_ok(directory);

	if (directory->inode != parent_file->inode) {
		fs->log("CREATE parent: %lu mismatch dir_inode: %lu (return error)",
			parent_file->inode, directory->inode);

		fbr_fuse_reply_err(request, ENOTDIR);

		fbr_inode_release(fs, &parent_file);
		fbr_dindex_release(fs, &directory);

		return;
	}

	fbr_inode_release(fs, &parent_file);

	fs->log("MKDIR found directory inode: %lu", directory->inode);

	struct fbr_path_name dirname;
	fbr_path_name_init(&dirname, name);

	// TODO look for duplicate

	struct fbr_file *file = fbr_file_alloc_new(fs, directory, &dirname);

	fbr_path_get_full(&file->path, &dirname, buf, sizeof(buf));
	fs->log("MKDIR new directory: inode: %lu path: '%s'", file->inode, dirname.name);

	assert(file->parent_inode == directory->inode);
	assert(file->state == FBR_FILE_INIT);
	assert_zero_dev(file->size);
	assert_zero_dev(file->generation);

	const struct fuse_ctx *fctx = fuse_req_ctx(request->fuse_req);
	assert(fctx);

	file->uid = fctx->uid;
	file->gid = fctx->gid;
	file->mode = S_IFDIR | mode;

	if (fs->store->directory_flush_f) {
		int ret = fs->store->directory_flush_f(fs, file, NULL, FBR_FLUSH_NONE);
		if (ret) {
			// TODO file is floating...?
			fbr_fuse_reply_err(request, EIO);
			fbr_dindex_release(fs, &directory);
			return;
		}
	} else {
		fbr_fuse_reply_err(request, EIO);
		fbr_dindex_release(fs, &directory);
		return;
	}

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(fs, file, &entry.attr);

	fbr_inode_add(fs, file);

	fbr_fuse_reply_entry(request, &entry);

	fbr_dindex_release(fs, &directory);
}
