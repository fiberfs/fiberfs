/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>

#include "fiberfs.h"
#include "fbr_store.h"

void
fbr_directory_expire(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_directory *new_directory)
{
	fbr_fs_ok(fs);
	assert_zero_dev(fs->shutdown);
	fbr_fuse_context_ok(fs->fuse_ctx);
	assert(fs->fuse_ctx->session);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert_zero_dev(directory->expired);

	if (new_directory) {
		fbr_directory_ok(new_directory);
		assert(new_directory->state == FBR_DIRSTATE_OK);
	}

	// If we have a TTL, files can never be forced to expire
	if (fs->config.dentry_ttl > 0 && !new_directory) {
		return;
	}

	struct fbr_file *file;

	TAILQ_FOREACH(file, &directory->file_list, file_entry) {
		fbr_file_ok(file);

		struct fbr_path_name filename;
		const char *sfilename = fbr_path_get_file(&file->path, &filename);

		struct fbr_file *new_file = NULL;
		int file_expired = 0;
		int file_changed = 0;
		int file_deleted = 0;

		if (new_directory) {
			new_file = fbr_directory_find_file(new_directory, sfilename);

			if (!new_file) {
				file_deleted = 1;
			} else if (file->inode != new_file->inode) {
				assert_dev(file->version != new_file->version);
				file_changed = 1;
			}
		} else {
			assert_dev(fs->config.dentry_ttl <= 0);
			file_expired = 1;
		}

		int ret;

		if (file_deleted) {
			ret = fuse_lowlevel_notify_delete(fs->fuse_ctx->session, directory->inode,
				file->inode, filename.name, filename.len);
			assert_dev(ret != -ENOSYS);
		} else if (file_expired || file_changed) {
			ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session,
				directory->inode, filename.name, filename.len);
			assert_dev(ret != -ENOSYS);
		}
	}
}
