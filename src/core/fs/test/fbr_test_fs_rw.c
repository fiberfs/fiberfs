/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/context/fbr_callback.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static void
_test_fs_rw_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	//conn->max_readahead
	//conn->max_background
	//FUSE_CAP_POSIX_ACL
	//fuse_lowlevel_notify_inval_inode()

	conn->want |= FUSE_CAP_SPLICE_WRITE;
	conn->want |= FUSE_CAP_SPLICE_MOVE;

	conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;

	// TODO
	conn->want &= ~FUSE_CAP_SPLICE_READ;

	struct fbr_directory *directory = fbr_directory_root_alloc(ctx->fs);
	fbr_directory_set_state(directory, FBR_DIRSTATE_OK);
}

static void
_test_fs_rw_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"OPEN ino: %lu flags: %d fh: %lu direct: %d", ino, fi->flags, fi->fh,
		fi->direct_io);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (fi->flags & O_CREAT) {
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** OPEN mode: create");
	}

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	} else if (!S_ISREG(file->mode)) {
		fbr_inode_release(fs, &file);
		assert_zero_dev(file);

		fbr_fuse_reply_err(request, EISDIR);
		return;
	}

	struct fbr_fio *fio = fbr_fio_alloc(fs, file);
	fbr_fio_ok(fio);

	if (fi->flags & O_RDONLY) {
		fio->read_only = 1;
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** OPEN mode: read only");
	} else {
		assert_dev(fi->flags & O_WRONLY || fi->flags & O_RDWR);
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** OPEN mode: read+write");
	}

	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** OPEN mode: append");
	}
	if (fi->flags & O_TRUNC) {
		fio->truncate = 1;
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** OPEN mode: truncate");
	}

	fi->fh = fbr_fs_int64(fio);

	//fi->keep_cache
	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);
}

static void
_test_fs_rw_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"READ ino: %lu size: %zu off: %ld fh: %lu", ino, size, off, fi->fh);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_file_ok(fio->file);

	fbr_fuse_reply_err(request, EIO);
}

static void
_test_fs_rw_write(struct fbr_request *request, fuse_ino_t ino, const char *buf, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"WRITE ino: %lu size: %zu off: %ld fh: %lu", ino, size, off, fi->fh);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_file_ok(fio->file);

	(void)buf;

	fbr_fuse_reply_err(request, EIO);
}

static void
_test_fs_rw_write_buf(struct fbr_request *request, fuse_ino_t ino, struct fuse_bufvec *bufv,
	off_t off, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"WRITE_BUF ino: %lu count: %zu off: %ld fh: %lu", ino, bufv->count, off, fi->fh);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_file_ok(fio->file);

	fbr_fuse_reply_err(request, EIO);
}

static void
_test_fs_rw_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "FLUSH ino: %lu fh: %lu",
		ino, fi->fh);

	fbr_fuse_reply_err(request, 0);
}

static void
_test_fs_rw_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "RELEASE ino: %lu fh: %lu",
		ino, fi->fh);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_free(fs, fio);

	fbr_fuse_reply_err(request, 0);
}

static void
_test_fs_rw_fsync(struct fbr_request *request, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "FSYNC ino: %lu datasync: %d fh: %lu",
		ino, datasync, fi->fh);

	fbr_fuse_reply_err(request, 0);
}

static const struct fbr_fuse_callbacks _TEST_FS_RW_CALLBACKS = {
	.init = _test_fs_rw_init,

	.getattr = fbr_test_fs_fuse_getattr,
	.lookup = fbr_test_fs_fuse_lookup,

	.opendir = fbr_test_fs_fuse_opendir,
	.readdir = fbr_test_fs_fuse_readdir,
	.releasedir = fbr_test_fs_fuse_releasedir,

	.open = _test_fs_rw_open,
	.read = _test_fs_rw_read,
	.write = _test_fs_rw_write,
	.write_buf = _test_fs_rw_write_buf,
	.flush = _test_fs_rw_flush,
	.release = _test_fs_rw_release,
	.fsync = _test_fs_rw_fsync,

	.forget = fbr_test_fs_fuse_forget,
	.forget_multi = fbr_test_fs_fuse_forget_multi
};

void
fbr_cmd_fs_test_rw_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *mount = cmd->params[0].value;

	int ret = fbr_fuse_test_mount(ctx, mount, &_TEST_FS_RW_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", mount);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", mount);
}
