/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <fcntl.h>
#include <pthread.h>
#include <time.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse.h"

void
fbr_fuse_LOCK(struct fbr_fuse_context *fuse_ctx, pthread_mutex_t *lock)
{
	assert(lock);

	if (!fuse_ctx) {
		pt_assert(pthread_mutex_lock(lock));
		return;
	}

	int ret;

	do {
		fbr_fuse_mounted(fuse_ctx);

		pthread_testcancel();

		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = 1000 * 1000 * 200;
		fbr_timespec_add_clock(&ts);

		ret = pthread_mutex_timedlock(lock, &ts);
	} while (ret == ETIMEDOUT);

	pt_assert(ret);
}

void
fbr_fuse_invalidate_dentry(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (fs->fuse_ctx) {
		fbr_fuse_mounted(fs->fuse_ctx);
		assert(fs->fuse_ctx->session);

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		fbr_rlog(FBR_LOG_FUSE, "INVAL DENTRY '%s' inode: %lu parent: %lu", filename.name,
			file->inode, file->parent_inode);

		int ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session,
			file->parent_inode, filename.name, filename.length);
		assert_dev(ret != -ENOSYS);
	}
}

void
fbr_fuse_invalidate_inode(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (fs->fuse_ctx) {
		fbr_fuse_mounted(fs->fuse_ctx);
		assert(fs->fuse_ctx->session);

		const char *type = "file";
		if (fbr_file_is_dir(file)) {
			type = "directory";
		}

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		fbr_rlog(FBR_LOG_FUSE, "INVAL INODE '%s' inode: %lu (%s)", filename.name,
			file->inode, type);

		int ret = fuse_lowlevel_notify_inval_inode(fs->fuse_ctx->session, file->inode,
			0, 0);
		assert_dev(ret != -ENOSYS);
	}
}

void
fbr_fuse_delete_dentry(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (fs->fuse_ctx) {
		fbr_fuse_mounted(fs->fuse_ctx);
		assert(fs->fuse_ctx->session);

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		fbr_rlog(FBR_LOG_FUSE, "INVAL DELETE '%s' inode: %lu parent: %lu", filename.name,
			file->inode, file->parent_inode);

		int ret = fuse_lowlevel_notify_delete(fs->fuse_ctx->session, file->parent_inode,
			file->inode, filename.name, filename.length);
		assert_dev(ret != -ENOSYS);
	}
}

int
fbr_fuse_check_access(const struct fuse_ctx *fctx, const struct fbr_file *file, int access)
{
	assert(fctx);
	fbr_file_ok(file);

	int file_mask = R_OK | W_OK | X_OK;
	assert(fbr_is_flag(access, file_mask));

	if (!fctx->uid) {
		return 1;
	}

	mode_t bits = 0;

	if (fctx->uid == file->uid) {
		bits = (file->mode >> 6) & file_mask;
	} else if (fctx->gid == file->gid) {
		bits = (file->mode >> 3) & file_mask;
	} else {
		bits = file->mode & file_mask;
	}

	if ((access & R_OK) && !(bits & R_OK)) {
		return 0;
	}
	if ((access & W_OK) && !(bits & W_OK)) {
		return 0;
	}
	if ((access & X_OK) && !(bits & X_OK)) {
		return 0;
	}

	return 1;
}
