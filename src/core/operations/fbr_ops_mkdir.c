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

	fbr_rlog(FBR_LOG_OP, "MKDIR req: %lu parent: %lu name: %s mode: %u", request->id, parent,
		name, mode);

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

	struct fbr_file *duplicate = fbr_directory_find_file(directory, dirname.name, dirname.len);
	if (duplicate) {
		fbr_fuse_reply_err(request, EEXIST);

		fbr_dindex_release(fs, &directory);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}

		return;
	}

	// Init file
	struct fbr_file *file = fbr_file_alloc_new(fs, directory, &dirname);
	assert(file->parent_inode == directory->inode);
	assert_dev(file->state == FBR_FILE_INIT);
	assert_zero_dev(file->size);
	assert_zero_dev(file->generation);

	const struct fuse_ctx *fctx = fuse_req_ctx(request->fuse_req);
	assert(fctx);

	file->uid = fctx->uid;
	file->gid = fctx->gid;
	file->mode = S_IFDIR | mode;

	fbr_inode_add(fs, file);

	char buf[FBR_PATH_MAX];
	fbr_path_get_full(&file->path, &dirname, buf, sizeof(buf));
	fbr_rlog(FBR_LOG_OP_MKDIR, "new directory: inode: %lu path: '%s'", file->inode,
		dirname.name);

	// Create a new root on the store
	struct fbr_directory *new_directory = fbr_directory_alloc(fs, &dirname, file->inode);
	fbr_directory_ok(new_directory);
	if (new_directory->state != FBR_DIRSTATE_LOADING) {
		fbr_fuse_reply_err(request, EEXIST);

		fbr_inode_release(fs, &file);
		fbr_dindex_release(fs, &directory);
		fbr_dindex_release(fs, &new_directory);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}

		return;
	}

	assert_dev(new_directory->state == FBR_DIRSTATE_LOADING);
	assert_zero_dev(new_directory->generation);
	new_directory->generation = 1;

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, new_directory, NULL, NULL, NULL, FBR_FLUSH_NONE);

	int ret = fbr_index_write(fs, &index_data);
	if (ret) {
		fbr_rlog(FBR_LOG_ERROR, "mkdir fbr_index_write(%s) failed", dirname.name);
		fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);

		fbr_fuse_reply_err(request, EEXIST);

		fbr_inode_release(fs, &file);
		fbr_dindex_release(fs, &directory);
		fbr_dindex_release(fs, &new_directory);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}

		return;
	}

	fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);

	fbr_index_data_free(&index_data);

	// Flush changes to parent
	if (fs->store->optional.directory_flush_f) {
		ret = fs->store->optional.directory_flush_f(fs, file, NULL, FBR_FLUSH_NONE);
	} else {
		ret = fbr_directory_flush(fs, file, NULL, FBR_FLUSH_NONE);
	}
	if (ret) {
		if (fs->store->index_delete_f) {
			int delete_ret = fs->store->index_delete_f(fs, new_directory);
			assert_zero(delete_ret);
		}

		fbr_fuse_reply_err(request, ret);

		fbr_inode_release(fs, &file);
		fbr_dindex_release(fs, &directory);
		fbr_dindex_release(fs, &new_directory);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}

		return;
	}

	assert(file->state == FBR_FILE_OK);

	// Fuse reply
	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(fs, file, &entry.attr);

	fbr_fuse_reply_entry(request, &entry);

	fbr_dindex_release(fs, &directory);
	fbr_dindex_release(fs, &new_directory);
	if (stale) {
		fbr_dindex_release(fs, &stale);
	}
}
