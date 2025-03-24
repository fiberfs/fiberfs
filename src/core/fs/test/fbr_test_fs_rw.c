/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/request/fbr_request.h"

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
	//FUSE_CAP_HANDLE_KILLPRIV

	conn->want |= FUSE_CAP_SPLICE_WRITE;
	conn->want |= FUSE_CAP_SPLICE_MOVE;

	conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;

	// TODO
	conn->want &= ~FUSE_CAP_SPLICE_READ;

	struct fbr_directory *root = fbr_directory_root_alloc(ctx->fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);
	fbr_directory_set_state(ctx->fs, root, FBR_DIRSTATE_OK);

	fbr_dindex_release(ctx->fs, &root);
}

static void
_test_fs_rw_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("OPEN ino: %lu flags: %d", ino, fi->flags);

	struct fbr_file *file = fbr_inode_take(fs, ino);

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
		fbr_test_logs("** OPEN mode: read only");
	} else {
		assert_dev(fi->flags & O_WRONLY || fi->flags & O_RDWR);
		fbr_test_logs("** OPEN mode: read+write");
	}

	if (fi->flags & O_CREAT) {
		fbr_test_logs("** OPEN mode: create");
	}
	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_test_logs("** OPEN mode: append");
	}
	if (fi->flags & O_TRUNC) {
		fio->truncate = 1;
		fbr_test_logs("** OPEN mode: truncate");
	}

	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);
}

static void
_test_fs_rw_create(struct fbr_request *request, fuse_ino_t parent, const char *name, mode_t mode,
    struct fuse_file_info *fi)
{
	fbr_request_ok(request);

	fbr_test_logs("CREATE parent: %lu name: '%s' mode: %d flags: %u", parent, name,
		mode, fi->flags);

	if (fi->flags & O_RDONLY) {
		fbr_test_logs("** CREATE mode: read only");
	} else {
		assert_dev(fi->flags & O_WRONLY || fi->flags & O_RDWR);
		fbr_test_logs("** CREATE mode: read+write");
	}

	if (fi->flags & O_CREAT) {
		fbr_test_logs("** CREATE mode: create");
	}
	if (fi->flags & O_APPEND) {
		fbr_test_logs("** CREATE mode: append");
	}
	if (fi->flags & O_TRUNC) {
		fbr_test_logs("** CREATE mode: truncate");
	}

	fbr_fuse_reply_err(request, EIO);
}

static void
_test_fs_rw_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_logs("READ ino: %lu off: %ld size: %zu", ino, off, size);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_file_ok(fio->file);

	fbr_fuse_reply_err(request, EIO);

	//fbr_fs_stat_add_count(&fs->stats.read_bytes, 0);
}

static void
_test_fs_rw_write(struct fbr_request *request, fuse_ino_t ino, const char *buf, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_logs("WRITE ino: %lu off: %ld size: %zu", ino, off, size);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_file_ok(fio->file);

	(void)buf;

	fbr_fuse_reply_err(request, EIO);

	//fbr_fs_stat_add_count(&fs->stats.write_bytes, 0);
}

static void
_test_fs_rw_write_buf(struct fbr_request *request, fuse_ino_t ino, struct fuse_bufvec *bufv,
	off_t off, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;

	fbr_test_logs("WRITE_BUF ino: %lu count: %zu off: %ld", ino, bufv->count, off);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_take(fio);
	fbr_file_ok(fio->file);

	fbr_fuse_reply_err(request, EIO);

	fbr_fio_release(fs, fio);

	//fbr_fs_stat_add_count(&fs->stats.write_bytes, );
}

static void
_test_fs_rw_flush(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;
	(void)fi;

	fbr_test_logs("FLUSH ino: %lu", ino);

	fbr_fuse_reply_err(request, 0);
}

static void
_test_fs_rw_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("RELEASE ino: %lu", ino);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_release(fs, fio);

	fbr_fuse_reply_err(request, 0);
}

static void
_test_fs_rw_fsync(struct fbr_request *request, fuse_ino_t ino, int datasync,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fs;
	(void)fi;

	fbr_test_logs("FSYNC ino: %lu datasync: %d", ino, datasync);

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
	.create = _test_fs_rw_create,
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

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;
}
