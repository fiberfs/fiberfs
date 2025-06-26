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
fbr_ops_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(fs->store);

	fs->log("LOOKUP req: %lu parent: %lu name: %s", request->id, parent, name);

	struct fbr_file *parent_file = fbr_inode_take(fs, parent);

	if (!parent_file || parent_file->state == FBR_FILE_EXPIRED) {
		fbr_fuse_reply_err(request, ENOTDIR);

		if (parent_file) {
			fbr_inode_release(fs, &parent_file);
		}
		assert_zero_dev(parent_file);

		return;
	}

	struct fbr_path_name parent_dirname;
	char buf[PATH_MAX];
	fbr_path_get_full(&parent_file->path, &parent_dirname, buf, sizeof(buf));

	fs->log("LOOKUP found parent_file: '%.*s':%zu (inode: %lu)",
		(int)parent_dirname.len, parent_dirname.name, parent_dirname.len,
		parent_file->inode);

	struct fbr_directory *directory = fbr_dindex_take(fs, &parent_dirname, 0);
	struct fbr_directory *stale_directory = NULL;

	if (directory && directory->inode > parent_file->inode) {
		fs->log("LOOKUP parent: %lu found newer dir_inode: %lu (return error)",
			parent_file->inode, directory->inode);

		fbr_fuse_reply_err(request, ENOTDIR);

		fbr_inode_release(fs, &parent_file);
		fbr_dindex_release(fs, &directory);

		return;
	} else if (directory && directory->inode < parent_file->inode) {
		fs->log("LOOKUP parent: %lu mismatch dir_inode: %lu (will make new)",
			parent_file->inode, directory->inode);
		stale_directory = directory;
		directory = NULL;
	}

	if (!directory) {
		if (fs->store->directory_load_f) {
			directory = fs->store->directory_load_f(fs, &parent_dirname,
				parent_file->inode);
		}

		if (!directory) {
			fbr_fuse_reply_err(request, EIO);

			fbr_inode_release(fs, &parent_file);

			if (stale_directory) {
				fbr_dindex_release(fs, &stale_directory);
				assert_zero_dev(stale_directory);
			}

			return;
		}

		assert(directory->inode == parent_file->inode);
	}

	fbr_directory_ok(directory);

	fbr_inode_release(fs, &parent_file);
	assert_zero_dev(parent_file);

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);
	fs->log("LOOKUP found directory: '%s' (inode: %lu)", dirname.name, directory->inode);

	size_t name_len = strlen(name);
	struct fbr_file *file = fbr_directory_find_file(directory, name, name_len);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);

		fbr_dindex_release(fs, &directory);
		assert_zero_dev(directory);

		if (stale_directory) {
			fbr_dindex_release(fs, &stale_directory);
			assert_zero_dev(stale_directory);
		}

		return;
	}

	fbr_file_ok(file);

	const char *fullname = fbr_path_get_full(&file->path, NULL, buf, sizeof(buf));
	fs->log("LOOKUP found file: '%s' (inode: %lu)", fullname, file->inode);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);
	assert(name_len == filename.len);
	assert_zero(strcmp(name, filename.name));

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(fs, file, &entry.attr);

	fbr_inode_add(fs, file);

	fbr_fuse_reply_entry(request, &entry);

	fbr_dindex_release(fs, &directory);
	assert_zero_dev(directory);

	if (stale_directory) {
		fbr_dindex_release(fs, &stale_directory);
		assert_zero_dev(stale_directory);
	}
}
