/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <string.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_rmdir(struct fbr_request *request, fuse_ino_t parent_inode, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(fs->store);

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
	} else if (file->parent_inode != parent_inode) {
		fbr_fuse_reply_err(request, EACCES);
		fbr_dindex_release(fs, &parent);
		return;
	}

	struct fbr_fullpath_name dirpath;
	fbr_path_get_full(&file->path, &dirpath);

	struct fbr_directory *directory = fbr_directory_get(fs, &dirpath.path, file->inode, 0, 0);
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

	fbr_inode_add(fs, file);
	fbr_dindex_release(fs, &parent);

	// Sync and delete directory first (existing references are stable)

	struct fbr_fs_timeout timeout;
	fbr_fs_timeout_init(&timeout);

	unsigned int version_matches = 0;
	fbr_id_t last_version = 0;
	int ret = EIO;

	do {
		if (!directory) {
			directory = fbr_directory_load(fs, &dirpath.path, file->inode, 1);
			if (!directory) {
				ret = EIO;
				break;
			} else if (directory->file_count) {
				ret = ENOTEMPTY;
				fbr_dindex_release(fs, &directory);
				break;
			}
		}

		if (fs->store->index_delete_f) {
			ret = fs->store->index_delete_f(fs, directory);
		}

		fbr_rlog(FBR_LOG_OP_RMDIR, "index_delete_f %d (%s)", ret, strerror(ret));

		if (!ret) {
			// Do nothing
		} else if (fbr_fs_is_timeout(fs, &timeout)) {
			ret = EIO;
		} else if (directory->version == last_version) {
			version_matches++;

			fbr_rlog(FBR_LOG_OP_RMDIR, "warning index hasn't changed (%u)",
				version_matches);

			if (version_matches >= FBR_MAX_VERSION_ERRORS) {
				ret = EIO;
			} else {
				fbr_sleep_backoff(timeout.attempts);
			}
		} else {
			last_version = directory->version;
			version_matches = 0;
		}

		fbr_dindex_release(fs, &directory);
	} while (ret == EAGAIN);

	assert_zero_dev(directory);

	if (ret) {
		fbr_fuse_reply_err(request, ret);
		fbr_inode_release(fs, &file);
		return;
	}

	// Delete from parent (existing references are stable)

	struct fbr_flush_data flush_data;
	fbr_flush_data_init(&flush_data, file, NULL, NULL, FBR_FLUSH_RMDIR);
	ret = fbr_fs_flush(fs, &flush_data);

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_err(request, ret);
}
