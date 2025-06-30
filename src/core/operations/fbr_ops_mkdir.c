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

	struct fbr_directory *stale;
	struct fbr_directory *directory = fbr_directory_from_inode(fs, parent, &stale);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}
		return;
	}

	struct fbr_path_name dirname;
	fbr_path_name_init(&dirname, name);

	// TODO look for duplicate
	// TODO write the new root and index before adding the file

	struct fbr_file *file = fbr_file_alloc_new(fs, directory, &dirname);

	char buf[PATH_MAX];
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
			if (stale) {
				fbr_dindex_release(fs, &stale);
			}
			return;
		}
	} else {
		fbr_fuse_reply_err(request, EIO);
		fbr_dindex_release(fs, &directory);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}
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
	if (stale) {
		fbr_dindex_release(fs, &stale);
	}
}
