/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <time.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/operations/fbr_operations.h"

static const struct fbr_fuse_callbacks _FUSE_DEFAULT_CALLBACKS = {
	.getattr = fbr_ops_getattr,
	.setattr = fbr_ops_setattr,
	.lookup = fbr_ops_lookup,

	.mkdir = fbr_ops_mkdir,
	.unlink = fbr_ops_unlink,
	.rmdir = fbr_ops_rmdir,
	.rename = fbr_ops_rename,

	.opendir = fbr_ops_opendir,
	.readdir = fbr_ops_readdir,
	.releasedir = fbr_ops_releasedir,

	.open = fbr_ops_open,
	.create = fbr_ops_create,
	.read = fbr_ops_read,
	.write = fbr_ops_write,
	.flush = fbr_ops_flush,
	.release = fbr_ops_release,
	.fsync = fbr_ops_fsync,

	.forget = fbr_ops_forget,
	.forget_multi = fbr_ops_forget_multi
};

const struct fbr_fuse_callbacks *FBR_FUSE_DEFAULT_CALLBACKS = &_FUSE_DEFAULT_CALLBACKS;

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
		ts.tv_nsec = 1000 * 1000 * 250;
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
		if (S_ISDIR(file->mode)) {
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
