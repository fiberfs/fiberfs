/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "OPEN req: %lu ino: %lu flags: %d", request->id, ino, fi->flags);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	} else if (!S_ISREG(file->mode)) {
		fbr_inode_release(fs, &file);
		fbr_fuse_reply_err(request, EISDIR);
		return;
	}

	int read_only = 0;

	if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: read+write");
	} else {
		read_only = 1;
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: read only");
	}

	struct fbr_fio *fio = fbr_fio_alloc(fs, file, read_only);
	fbr_fio_ok(fio);

	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: append");
	}
	if (fi->flags & O_TRUNC) {
		// TODO should we zero out file->size here?
		fio->truncate = 1;
		fbr_rlog(FBR_LOG_OP_OPEN, "flags: truncate");
	}
	if (fi->flags & O_CREAT) {
		fbr_ABORT("O_CREAT used in OPEN?");
	}

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);

	fbr_inode_release(fs, &file);
}

void
fbr_ops_create(struct fbr_request *request, fuse_ino_t parent, const char *name, mode_t mode,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "CREATE req: %lu parent: %lu name: '%s' mode: %d flags: %u",
		request->id, parent, name, mode, fi->flags);

	int error = fbr_check_name(name);
	if (error) {
		fbr_fuse_reply_err(request, error);
		return;
	}

	struct fbr_directory *stale;
	struct fbr_directory *directory = fbr_directory_from_inode(fs, parent, &stale);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}
		return;
	}

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, name);

	struct fbr_file *file = fbr_file_alloc_new(fs, directory, &filename);

	struct fbr_fullpath_name fullpath;
	fbr_path_get_full(&file->path, &fullpath);
	fbr_rlog(FBR_LOG_OP_CREATE, "new file: inode: %lu path: '%s'", file->inode,
		fullpath.path.name);

	assert(file->parent_inode == directory->inode);
	assert(file->state == FBR_FILE_INIT);
	assert_zero_dev(file->size);
	assert_zero_dev(file->generation);

	const struct fuse_ctx *fctx = fuse_req_ctx(request->fuse_req);
	assert(fctx);

	file->uid = fctx->uid;
	file->gid = fctx->gid;
	file->mode = mode;

	struct fbr_fio *fio = fbr_fio_alloc(fs, file, 0);
	fbr_fio_ok(fio);

	if (fi->flags & O_RDONLY) {
		fbr_ABORT("O_RDONLY used in CREATE?");
	} else {
		assert_dev(fi->flags & O_WRONLY || fi->flags & O_RDWR);
		fbr_rlog(FBR_LOG_OP_CREATE, "flags: read+write");
	}

	assert(fi->flags & O_CREAT);

	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_rlog(FBR_LOG_OP_CREATE, "flags: append");
	}
	if (fi->flags & O_TRUNC) {
		fio->truncate = 1;
		fbr_rlog(FBR_LOG_OP_CREATE, "flags: truncate");
	}

	if (S_ISREG(mode)) {
		fbr_rlog(FBR_LOG_OP_CREATE, "mode: file");
	} else {
		if (S_ISDIR(mode)) {
			fbr_rlog(FBR_LOG_OP_CREATE, "mode: directory");
		} else {
			fbr_rlog(FBR_LOG_OP_CREATE, "mode: other");
		}

		fbr_fuse_reply_err(request, EIO);

		fbr_dindex_release(fs, &directory);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}

		return;
	}

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	struct fuse_entry_param entry;
	fbr_zero(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(fs, file, &entry.attr);

	// Dentry reference
	struct fbr_file *dref = fbr_inode_take(fs, file->inode);
	assert(dref == file);

	fbr_fuse_reply_create(request, &entry, fi);

	fbr_dindex_release(fs, &directory);
	if (stale) {
		fbr_dindex_release(fs, &stale);
	}
}
