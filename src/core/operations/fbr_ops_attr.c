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
	(void)fi;

	fbr_rlog(FBR_LOG_OP, "SETATTR req: %lu ino: %lu to_set: %d", request->id, ino, to_set);

	struct fbr_file *file = fbr_inode_take(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	// TODO we need to lock this entire transaction pass flush its own copy of attr
	// Set the file times during init and writing

	struct stat st_before, st_after;
	fbr_file_attr(fs, file, &st_before);
	memcpy(&st_after, &st_before, sizeof(st_after));

	if (fbr_is_flag(to_set, FUSE_SET_ATTR_MODE)) {
		st_after.st_mode = attr->st_mode;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_UID)) {
		st_after.st_uid = attr->st_uid;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_GID)) {
		st_after.st_gid = attr->st_gid;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_SIZE)) {
		if (attr->st_size >= 0) {
			st_after.st_size = attr->st_size;
		}
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_CTIME)) {
		st_after.st_ctim = attr->st_ctim;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_MTIME)) {
		st_after.st_mtim = attr->st_mtim;
	}
	if (fbr_is_flag(to_set, FUSE_SET_ATTR_MTIME_NOW)) {
		double now = fbr_get_time();
		fbr_convert_time(now, &st_after.st_mtim);
	}

	int attr_changed = 0;
	int size_truncated = 0;
	int size_extended = 0;

	if (st_after.st_size > st_before.st_size) {
		size_extended = 1;
		st_before.st_size = st_after.st_size;
	} else if (st_after.st_size < st_before.st_size) {
		size_truncated = 1;
		st_before.st_size = st_after.st_size;
	}

	if (memcmp(&st_before, &st_after, sizeof(st_before))) {
		attr_changed = 1;
	}

	if (!attr_changed && !size_truncated && !size_extended) {
		fbr_inode_release(fs, &file);
		fbr_fuse_reply_attr(request, &st_after, fbr_fs_dentry_ttl(fs));

		fbr_rlog(FBR_LOG_OP_ATTR, "SETATTR no change, skipping");

		return;
	}

	if (attr_changed || size_extended) {
		struct fbr_flush_data flush_data;
		fbr_flush_data_init(&flush_data, file, &st_after, NULL, FBR_FLUSH_ATTR);
		int ret = fbr_fs_flush(fs, &flush_data);

		if (ret) {
			fbr_inode_release(fs, &file);
			fbr_fuse_reply_err(request, ret);
			return;
		}

		fbr_file_set_attr(fs, file, &st_after);
	}

	fbr_ASSERT(!size_truncated, "TODO implement size_truncated");

	fbr_inode_release(fs, &file);

	fbr_fuse_reply_attr(request, &st_after, fbr_fs_dentry_ttl(fs));
}
