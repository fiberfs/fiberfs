/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <sys/stat.h>
#include <sys/types.h>

#include "fiberfs.h"
#include "core/context/fbr_callback.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

#define _TEST_FS_FUSE_TTL_SEC		2.0

static void
_test_fs_init_directory(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_path_name dirname;
	fbr_path_get_dir(&directory->dirname, &dirname);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** INIT directory: '%.*s':%zu",
		(int)dirname.len, dirname.name, dirname.len);

	char name[32];
	strncpy(name, "fiberX", sizeof(name));
	assert(name[5] == 'X');

	for (size_t i = 0; i < 4; i++) {
		mode_t fmode = S_IFREG | 0444;

		name[5] = i + '1';

		struct fbr_path_name filename;
		fbr_path_name_init(&filename, name);

		(void)fbr_file_alloc(fs, directory, &filename, fmode);
	}

	strncpy(name, "fiber_dirX", sizeof(name));
	assert(name[9] == 'X');

	for (size_t i = 0; i < 4; i++) {
		mode_t fmode = S_IFDIR | 0444;

		name[9] = i + '1';

		struct fbr_path_name filename;
		fbr_path_name_init(&filename, name);

		(void)fbr_file_alloc(fs, directory, &filename, fmode);
	}

	fbr_directory_set_state(directory, FBR_DIRSTATE_OK);
}

static void
_test_fs_fuse_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);

	struct fbr_fs *fs = ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);

	_test_fs_init_directory(fs, root);
}

static void
_test_fs_fuse_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fi;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "GETATTR ino: %lu", ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_file_ok(file);

	struct stat st;
	fbr_file_attr(file, &st);

	fbr_inode_release(fs, &file);
	assert_zero_dev(file);

	fbr_fuse_reply_attr(request, &st, _TEST_FS_FUSE_TTL_SEC);
}

static void
_test_fs_fuse_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "LOOKUP parent: %lu name: %s",
		parent, name);

	struct fbr_file *parent_file = fbr_inode_take(fs, parent);

	if (!parent_file) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	struct fbr_path_name parent_dirname;
	fbr_path_get_dir(&parent_file->path, &parent_dirname);

	fbr_inode_release(fs, &parent_file);
	assert_zero_dev(parent_file);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** LOOKUP parent: '%.*s':%zu",
		(int)parent_dirname.len, parent_dirname.name, parent_dirname.len);

	struct fbr_directory *directory = fbr_dindex_take(fs, &parent_dirname);

	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	fbr_directory_ok(directory);

	struct fbr_path_name dirname;
	fbr_path_get_dir(&directory->dirname, &dirname);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** LOOKUP directory: '%.*s':%zu",
		(int)dirname.len, dirname.name, dirname.len);

	struct fbr_file *file = fbr_directory_find_file(directory, name);

	if (!file) {
		fbr_dindex_release(fs, &directory);
		assert_zero_dev(directory);

		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_file_ok(file);
	assert(file->inode);

	struct fbr_path_name filename;
	fbr_path_get_full(&file->path, &filename);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** LOOKUP file: '%.*s':%zu",
		(int)filename.len, filename.name, filename.len);

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = _TEST_FS_FUSE_TTL_SEC;
	entry.entry_timeout = _TEST_FS_FUSE_TTL_SEC;
	entry.ino = file->inode;
	fbr_file_attr(file, &entry.attr);

	fbr_inode_add(fs, file);
	fbr_dindex_release(fs, &directory);
	assert_zero_dev(directory);

	fbr_fuse_reply_entry(request, &entry);
}

static void
_test_fs_fuse_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "OPENDIR ino: %lu", ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	struct fbr_path_name dirname;
	fbr_path_get_full(&file->path, &dirname);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "** OPENDIR directory: '%.*s':%zu",
		(int)dirname.len, dirname.name, dirname.len);

	fbr_inode_release(fs, &file);
	assert_zero_dev(file);

	struct fbr_directory *directory = fbr_dindex_take(fs, &dirname);

	if (!directory) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	struct fbr_dreader *reader = fbr_dreader_alloc(fs, directory);
	fbr_dreader_ok(reader);

	fi->fh = fbr_fs_int64(reader);

	//fi->cache_readdir
	fi->cache_readdir = 1;

	fbr_fuse_reply_open(request, fi);
}

static void
_test_fs_fuse_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"READDIR ino: %lu size: %zu off: %ld fh: %lu", ino, size, off, fi->fh);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	if (reader->end) {
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERY_VERBOSE, "READDIR return: end");
		fbr_fuse_reply_buf(request, NULL, 0);
		return;
	}

	struct fbr_directory *directory = reader->directory;
	fbr_directory_ok(directory);

	struct fbr_dirbuffer dbuf;
	fbr_dirbuffer_init(&dbuf, size);

	if (!dbuf.full && !reader->read_dot) {
		fbr_file_ok(directory->file);

		struct stat st;
		fbr_file_attr(directory->file, &st);

		fbr_dirbuffer_add(request, &dbuf, ".", 1, &st);

		if (!dbuf.full) {
			reader->read_dot = 1;
		}
	}
	if (!dbuf.full && !reader->read_dotdot) {
		struct fbr_file *parent;
		if (directory->file->parent_inode) {
			parent = fbr_inode_take(fs, directory->file->parent_inode);
		} else {
			parent = directory->file;
		}
		fbr_file_ok(parent);

		struct stat st;
		fbr_file_attr(parent, &st);

		fbr_dirbuffer_add(request, &dbuf, "..", 2, &st);

		if (!dbuf.full) {
			reader->read_dotdot = 1;
		}
	}

	if (dbuf.full) {
		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERY_VERBOSE, "READDIR return: %zu",
			dbuf.pos);
		fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
		return;
	}

	struct fbr_file *file = reader->position;

	TAILQ_FOREACH_FROM(file, &directory->file_list, file_entry) {
		fbr_file_ok(file);

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERY_VERBOSE,
			"READDIR filename: '%.*s' inode: %lu", (int)filename.len, filename.name,
			file->inode);

		struct stat st;
		fbr_file_attr(file, &st);

		fbr_dirbuffer_add(request, &dbuf, filename.name, filename.len, &st);

		reader->position = file;

		if (dbuf.full) {
			fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERY_VERBOSE,
				"READDIR return: %zu", dbuf.pos);
			fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
			return;
		}
	}

	reader->end = 1;

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERY_VERBOSE, "READDIR return: %zu", dbuf.pos);
	fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
}

static void
_test_fs_fuse_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "RELEASEDIR ino: %lu fh: %lu",
		ino, fi->fh);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);
	fbr_dreader_free(fs, reader);

	fbr_fuse_reply_err(request, 0);
}

static void
_test_fs_fuse_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"OPEN ino: %lu flags: %d fh: %lu direct: %d", ino, fi->flags, fi->fh,
		fi->direct_io);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	} else if (!S_ISREG(file->mode)) {
		fbr_inode_release(fs, &file);
		assert_zero_dev(file);

		fbr_fuse_reply_err(request, EISDIR);
		return;
	} else if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		fbr_inode_release(fs, &file);
		assert_zero_dev(file);

		fbr_fuse_reply_err(request, EROFS);
		return;
	}

	fi->fh = fbr_fs_int64(file);

	//fi->keep_cache
	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);
}

static void
_test_fs_fuse_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	fbr_request_ok(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE,
		"READ ino: %lu size: %zu off: %ld flags: %d fh: %lu", ino, size, off, fi->flags,
		fi->fh);

	struct fbr_file *file = fbr_fh_file(fi->fh);

	fbr_ASSERT(file->size == 0, "TODO");
	(void)size;
	(void)off;

	fbr_fuse_reply_buf(request, NULL, 0);
}

static void
_test_fs_fuse_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "RELEASE ino: %lu flags: %d fh: %lu",
		ino, fi->flags, fi->fh);

	struct fbr_file *file = fbr_fh_file(fi->fh);
	fbr_inode_release(fs, &file);
	assert_zero_dev(file);

	fbr_fuse_reply_err(request, 0);
}

static void
_test_fs_fuse_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "FORGET ino: %lu nlookup: %lu",
		ino, nlookup);

	fbr_inode_forget(fs, ino, nlookup);

	fbr_fuse_reply_none(request);
}

static void
_test_fs_fuse_forget_multi(struct fbr_request *request, size_t count, struct fuse_forget_data *forgets)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_log(fbr_test_fuse_ctx(), FBR_LOG_VERBOSE, "FORGET_MULTI count: %zu", count);

	for (size_t i = 0; i < count; i++) {
		fbr_inode_forget(fs, forgets[i].ino, forgets[i].nlookup);
	}

	fbr_fuse_reply_none(request);
}

static const struct fbr_fuse_callbacks _TEST_FS_FUSE_CALLBACKS = {
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

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_FUSE_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", cmd->params[0].value);
}
