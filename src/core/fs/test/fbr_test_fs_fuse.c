/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <sys/stat.h>
#include <sys/types.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/fuse/fbr_fuse_ops.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

#define _TEST_FS_FUSE_TTL_SEC		2.0

static void
_test_fs_fuse_init(void *userdata, struct fuse_conn_info *conn)
{
	struct fbr_fuse_context *ctx;

	ctx = (struct fbr_fuse_context*)userdata;

	fbr_fuse_mounted(ctx);
	assert(conn);

	struct fbr_directory *root = fbr_directory_root_alloc(&ctx->fs);

	mode_t fmode = S_IFREG | 0444;

	(void)fbr_file_alloc(&ctx->fs, root, "fiber1", 6, fmode);
	(void)fbr_file_alloc(&ctx->fs, root, "fiber2", 6, fmode);

	fbr_directory_set_state(root, FBR_DIRSTATE_OK);
}

static void
_test_fs_fuse_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	(void)fi;

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "GETATTR ino: %lu", ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		int ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_getattr fuse_reply_err %d", ret);
		return;
	}

	fbr_file_ok(file);

	struct stat st;
	fbr_file_attr(file, &st);

	fbr_inode_release(fs, file);

	int ret = fuse_reply_attr(req, &st, _TEST_FS_FUSE_TTL_SEC);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_getattr fuse_reply_attr %d", ret);
}

static void
_test_fs_fuse_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "LOOKUP parent: %lu name: %s",
		parent, name);

	struct fbr_directory *directory = fbr_dindex_get(fs, parent);

	if (!directory) {
		int ret = fuse_reply_err(req, ENOTDIR);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_lookup fuse_reply_err %d", ret);
		return;
	}

	struct fbr_file *file = fbr_directory_find(directory, name);

	if (!file) {
		fbr_dindex_release(fs, directory);

		int ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_lookup fuse_reply_err %d", ret);
		return;
	}

	fbr_file_ok(file);
	assert(file->inode);

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = _TEST_FS_FUSE_TTL_SEC;
	entry.entry_timeout = _TEST_FS_FUSE_TTL_SEC;
	entry.ino = file->inode;
	fbr_file_attr(file, &entry.attr);

	fbr_inode_add(fs, file);
	fbr_dindex_release(fs, directory);

	int ret = fuse_reply_entry(req, &entry);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_lookup fuse_reply_entry %d", ret);
}

static void
_test_fs_fuse_opendir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "OPENDIR ino: %lu", ino);

	struct fbr_directory *directory = fbr_dindex_get(fs, ino);

	if (!directory) {
		int ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_opendir fuse_reply_err %d", ret);
		return;
	}

	// fh owns the file ref now
	fi->fh = fbr_directory_to_fh(directory);

	//fi->cache_readdir
	fi->cache_readdir = 1;

	int ret = fuse_reply_open(req, fi);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_opendir fuse_reply_open %d", ret);
}

static void
_test_fs_fuse_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "READDIR ino: %lu size: %zu off: %ld fh: %lu",
		ino, size, off, fi->fh);

	struct fbr_directory *directory = fbr_directory_fh(fi->fh);

	// TODO we need to sort out how a directory relates to its inode
	struct fbr_file *file = fbr_inode_take(fs, directory->inode);
	fbr_file_ok(file);

	struct stat st;
	fbr_file_attr(file, &st);

	fbr_inode_release(fs, file);

	TAILQ_FOREACH(file, &directory->file_list, file_entry) {
		fbr_file_ok(file);

		fbr_test_log(test_ctx, FBR_LOG_VERY_VERBOSE, "READDIR filename: '%s' inode: %lu",
			fbr_filename_get(&file->filename), file->inode);
	}

	int ret = fuse_reply_buf(req, NULL, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_readdir fuse_reply_buf %d", ret);
}

static void
_test_fs_fuse_releasedir(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "RELEASEDIR ino: %lu fh: %lu", ino, fi->fh);

	struct fbr_directory *directory = fbr_directory_fh(fi->fh);
	fbr_dindex_release(fs, directory);

	int ret = fuse_reply_err(req, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_releasedir fuse_reply_err %d", ret);
}

static void
_test_fs_fuse_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "OPEN ino: %lu flags: %d fh: %lu direct: %d",
		ino, fi->flags, fi->fh, fi->direct_io);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		int ret = fuse_reply_err(req, ENOENT);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_open fuse_reply_err %d", ret);
		return;
	} else if (!S_ISREG(file->mode)) {
		fbr_inode_release(fs, file);

		int ret = fuse_reply_err(req, EISDIR);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_open fuse_reply_err %d", ret);
		return;
	} else if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		fbr_inode_release(fs, file);

		int ret = fuse_reply_err(req, EROFS);
		fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_open fuse_reply_err %d", ret);
		return;
	}

	// fh owns the file ref now
	fi->fh = fbr_file_to_fh(file);

	//fi->keep_cache
	fi->keep_cache = 1;

	int ret = fuse_reply_open(req, fi);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_open fuse_reply_open %d", ret);
}

static void
_test_fs_fuse_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "READ ino: %lu size: %zu off: %ld flags: %d"
		" fh: %lu", ino, size, off, fi->flags, fi->fh);

	struct fbr_file *file = fbr_file_fh(fi->fh);

	fbr_ASSERT(file->size == 0, "TODO");
	(void)size;
	(void)off;

	int ret = fuse_reply_buf(req, NULL, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_read fuse_reply_buf %d", ret);
}

static void
_test_fs_fuse_release(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);
	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "RELEASE ino: %lu flags: %d fh: %lu",
		ino, fi->flags, fi->fh);

	struct fbr_file *file = fbr_file_fh(fi->fh);
	fbr_inode_release(fs, file);

	int ret = fuse_reply_err(req, 0);
	fbr_test_fuse_ERROR(ret, ctx, NULL, "_test_ops_release fuse_reply_err %d", ret);
}

static void
_test_fs_fuse_forget(fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FORGET ino: %lu nlookup: %lu", ino, nlookup);

	fbr_inode_forget(fs, ino, nlookup);

	if (req) {
		fuse_reply_none(req);
	}
}

static void
_test_fs_fuse_forget_multi(fuse_req_t req, size_t count, struct fuse_forget_data *forgets)
{
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(req);
	struct fbr_fs *fs = &ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_test_context *test_ctx = (struct fbr_test_context*)ctx->context_priv;
	fbr_test_context_ok(test_ctx);

	fbr_test_log(test_ctx, FBR_LOG_VERBOSE, "FORGET_MULTI count: %zu", count);

	for (size_t i = 0; i < count; i++) {
		_test_fs_fuse_forget(NULL, forgets[i].ino, forgets[i].nlookup);
	}

	fuse_reply_none(req);
}

static const struct fuse_lowlevel_ops _TEST_FS_FUSE_OPS = {
	.init = _test_fs_fuse_init,

	.getattr = _test_fs_fuse_getattr,
	.lookup = _test_fs_fuse_lookup,

	.opendir = _test_fs_fuse_opendir,
	.readdir = _test_fs_fuse_readdir,
	.releasedir = _test_fs_fuse_releasedir,

	.open = _test_fs_fuse_open,
	.read = _test_fs_fuse_read,
	.release = _test_fs_fuse_release,

	.forget = _test_fs_fuse_forget,
	.forget_multi = _test_fs_fuse_forget_multi
};

void
fbr_cmd_fs_test_fuse_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_FUSE_OPS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", cmd->params[0].value);
}
