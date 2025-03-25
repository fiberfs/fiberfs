/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
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
	conn->want &= ~FUSE_CAP_SPLICE_READ;

	// TODO fuse said this breaks distributed append if enabled
	conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;

	// Note: we dont init content on demand, so directories cannot be purged in this sim

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
		fbr_test_logs("** OPEN flags: read only");
	} else {
		assert_dev(fi->flags & O_WRONLY || fi->flags & O_RDWR);
		fbr_test_logs("** OPEN flags: read+write");
	}

	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_test_logs("** OPEN flags: append");
	}
	if (fi->flags & O_TRUNC) {
		fio->truncate = 1;
		fbr_test_logs("** OPEN flags: truncate");
	}
	if (fi->flags & O_CREAT) {
		fbr_ABORT("O_CREAT used in OPEN?");
	}

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);
}

static void
_test_fs_rw_create(struct fbr_request *request, fuse_ino_t parent, const char *name, mode_t mode,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("CREATE parent: %lu name: '%s' mode: %d flags: %u", parent, name,
		mode, fi->flags);

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

	fbr_test_logs("** CREATE found parent_file: '%s' (inode: %lu)",
		parent_dirname.name, parent_file->inode);

	struct fbr_directory *directory = fbr_dindex_take(fs, &parent_dirname, 0);

	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);

		fbr_inode_release(fs, &parent_file);
		return;
	}

	fbr_directory_ok(directory);

	if (directory->inode != parent_file->inode) {
		fbr_test_logs("** CREATE parent: %lu mismatch dir_inode: %lu (return error)",
			parent_file->inode, directory->inode);

		fbr_fuse_reply_err(request, ENOTDIR);

		fbr_inode_release(fs, &parent_file);
		fbr_dindex_release(fs, &directory);

		return;
	}

	fbr_inode_release(fs, &parent_file);
	assert_zero_dev(parent_file);

	fbr_test_logs("** CREATE found directory inode: %lu", directory->inode);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, name);

	struct fbr_file *file = fbr_file_alloc_new(fs, directory, &filename);

	fbr_path_get_full(&file->path, &filename, buf, sizeof(buf));
	fbr_test_logs("** CREATE new file: inode: %lu path: '%s'", file->inode, filename.name);

	assert(file->parent_inode == directory->inode);
	assert(file->state == FBR_FILE_NEW);

	file->mode = mode;

	const struct fuse_ctx *fctx = fuse_req_ctx(request->fuse_req);
	assert(fctx);

	file->uid = fctx->uid;
	file->gid = fctx->gid;

	struct fbr_fio *fio = fbr_fio_alloc(fs, file);
	fbr_fio_ok(fio);

	if (fi->flags & O_RDONLY) {
		fbr_ABORT("O_RDONLY used in CREATE?");
	} else {
		assert_dev(fi->flags & O_WRONLY || fi->flags & O_RDWR);
		fbr_test_logs("** CREATE flags: read+write");
	}

	assert(fi->flags & O_CREAT);

	if (fi->flags & O_APPEND) {
		fio->append = 1;
		fbr_test_logs("** CREATE flags: append");
	}
	if (fi->flags & O_TRUNC) {
		fio->truncate = 1;
		fbr_test_logs("** CREATE flags: truncate");
	}

	if (S_ISREG(mode)) {
		fbr_test_logs("** CREATE mode: file");
	} else if (S_ISDIR(mode)) {
		fbr_test_logs("** CREATE mode: directory");
	} else {
		fbr_test_logs("** CREATE mode: other");

		fbr_fuse_reply_err(request, EIO);

		fbr_dindex_release(fs, &directory);

		return;
	}

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(file, &entry.attr);

	fbr_inode_add(fs, file);

	fbr_fuse_reply_create(request, &entry, fi);

	fbr_dindex_release(fs, &directory);
	assert_zero_dev(directory);
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

	fbr_test_logs("WRITE ino: %lu off: %ld size: %zu", ino, off, size);
	assert(off >= 0);
	assert(size);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_take(fio);
	fbr_file_ok(fio->file);

	struct fbr_wbuffer *wbuffer = fbr_wbuffer_get(fs, fio, off, size);

	size_t written = 0;
	while (written < size) {
		fbr_wbuffer_ok(wbuffer);

		assert((size_t)off >= wbuffer->offset);
		off -= wbuffer->offset;

		size_t wsize = size - written;
		if (wsize > wbuffer->size) {
			assert_dev(wbuffer->end == wbuffer->size);
			wsize = wbuffer->size;
		} else {
			assert_dev(wbuffer->end >= wsize + off);
		}

		memcpy(wbuffer->buffer + off, buf, wsize);

		off = wbuffer->offset + wbuffer->size;
		written += wsize;

		wbuffer = wbuffer->next;
	}

	assert_dev(written == size);
	fbr_fuse_reply_write(request, written);

	fbr_fio_release(fs, fio);

	fbr_fs_stat_add_count(&fs->stats.write_bytes, written);
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
