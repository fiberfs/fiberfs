/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fi;

	fbr_rlog(FBR_LOG_OP, "GETATTR req: %lu ino: %lu", request->id, ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	struct stat st;
	fbr_file_attr(fs, file, &st);

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_attr(request, &st, fbr_fs_dentry_ttl(fs));
}

void
fbr_ops_setattr(struct fbr_request *request, fuse_ino_t ino, struct stat *attr, int to_set,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(fs->store);
	(void)fi;

	fbr_rlog(FBR_LOG_OP, "SETATTR req: %lu ino: %lu to_set: %d", request->id, ino, to_set);

	struct fbr_file *file = fbr_inode_take(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	// TODO we need to lock this entire transaction pass flush its own copy of attr
	// Set the file times during init and writing

	struct stat st_before;
	fbr_file_attr(fs, file, &st_before);
	int attr_changed = 0;
	int size_changed = 0;

	if (fbr_is_flag(to_set, FUSE_SET_ATTR_MODE)) {
		file->mode = attr->st_mode;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_UID)) {
		file->uid = attr->st_uid;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_GID)) {
		file->gid = attr->st_gid;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_SIZE)) {
		if (attr->st_size >= 0 && file->size != (unsigned long)attr->st_size) {
			file->size = attr->st_size;
			size_changed = 1;
		}
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_CTIME)) {
		file->ctime = fbr_convert_timespec(&attr->st_ctim);
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_MTIME)) {
		file->mtime = fbr_convert_timespec(&attr->st_mtim);
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_ATIME)) {
		file->atime = fbr_convert_timespec(&attr->st_atim);
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_MTIME_NOW)) {
		file->mtime = fbr_get_time();
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_ATIME_NOW)) {
		file->atime = fbr_get_time();
	}

	struct stat st_after;
	fbr_file_attr(fs, file, &st_after);
	st_after.st_size = st_before.st_size;

	if (memcmp(&st_before, &st_after, sizeof(st_before))) {
		attr_changed = 1;
	}

	if (!attr_changed && !size_changed) {
		fbr_inode_release(fs, &file);
		fbr_fuse_reply_attr(request, &st_after, fbr_fs_dentry_ttl(fs));

		fbr_rlog(FBR_LOG_OP_ATTR, "SETATTR no change, skipping");

		return;
	}

	if (attr_changed) {
		int ret = EIO;

		if (fs->store->optional.directory_flush_f) {
			ret = fs->store->optional.directory_flush_f(fs, file, NULL, FBR_FLUSH_ATTR);
		} else {
			ret = fbr_directory_flush(fs, file, NULL, FBR_FLUSH_ATTR);
		}

		if (ret) {
			fbr_inode_release(fs, &file);
			fbr_fuse_reply_err(request, ret);
			return;
		}
	}

	fbr_ASSERT(!size_changed, "TODO implement size_changed");

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_attr(request, &st_after, fbr_fs_dentry_ttl(fs));
}
