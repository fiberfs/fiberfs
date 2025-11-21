/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
#include <sys/types.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/request/fbr_request.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static void
_test_fs_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert(conn);

	struct fbr_fs *fs = ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_path_name filename;
	mode_t fmode = S_IFREG | 0444;

	fbr_path_name_init(&filename, "fiber1");
	struct fbr_file *file = fbr_file_alloc(fs, root, &filename);
	file->mode = fmode;
	file->state = FBR_FILE_OK;

	fbr_path_name_init(&filename, "fiber2");
	file = fbr_file_alloc(fs, root, &filename);
	file->mode = fmode;
	file->state = FBR_FILE_OK;

	fmode = S_IFDIR | 0555;

	fbr_path_name_init(&filename, "dir1");
	file = fbr_file_alloc(fs, root, &filename);
	file->mode = fmode;
	file->state = FBR_FILE_OK;

	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	fbr_inode_add(fs, file);

	struct fbr_directory *dir1 = fbr_directory_alloc(fs, &filename, file->inode);
	fbr_directory_ok(dir1);
	assert(dir1->state == FBR_DIRSTATE_LOADING);

	fbr_directory_set_state(fs, dir1, FBR_DIRSTATE_OK);

	fbr_inode_release(fs, &file);
	fbr_dindex_release(fs, &dir1);
	fbr_dindex_release(fs, &root);
}

static const struct fbr_fuse_callbacks _TEST_FS_INIT_CALLBACKS = {
	.init = _test_fs_init
};

void
fbr_cmd_fs_test_init_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_INIT_CALLBACKS);
	fbr_test_ERROR(ret, "fs init fuse mount failed: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	struct fbr_path_name name;
	fbr_directory_name(root, &name);

	fbr_test_ERROR(name.length, "root dirname has length");
	fbr_test_ASSERT(name.name, "dirname is null");
	fbr_test_ERROR(strcmp(name.name, ""), "root dirname not empty")

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
	fbr_file_ok(root_file);

	fbr_path_get_file(&root_file->path, &name);

	fbr_test_ASSERT(root->file == root_file, "Bad root file");
	fbr_test_ERROR(root_file->parent_inode, "root has a parent inode");
	fbr_test_ASSERT(root_file->state == FBR_FILE_OK, "root_file not FBR_FILE_OK");
	fbr_test_ERROR(name.length, "root_file name has length");
	fbr_test_ASSERT(name.name, "filename is null");
	fbr_test_ERROR(strcmp(name.name, ""), "root_file not empty")

	fbr_inode_release(fs, &root_file);
	fbr_dindex_release(fs, &root);
	assert_zero_dev(root_file);
	assert_zero_dev(root);

	fbr_path_name_init(&name, "dir1");
	struct fbr_directory *dir1 = fbr_dindex_take(fs, &name, 1);
	fbr_directory_ok(dir1);
	fbr_test_ASSERT(dir1->state == FBR_DIRSTATE_OK, "bad dir1 state %d", root->state);

	fbr_dindex_release(fs, &dir1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_init mounted: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_chunk)=%zu",
		sizeof(struct fbr_chunk));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_body)=%zu",
		sizeof(struct fbr_body));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_chunk_slab)=%zu",
		(sizeof(struct fbr_chunk) * FBR_BODY_SLAB_DEFAULT_CHUNKS) +
			sizeof(struct fbr_chunk_slab));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_file)=%zu",
		sizeof(struct fbr_file));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_directory)=%zu",
		sizeof(struct fbr_directory));
}

void
fbr_cmd_fs_test_dentry_ttl_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ttl = fbr_test_parse_long(cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fs->config.dentry_ttl = (double)ttl / 1000.0;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs dentry ttl %lf", fs->config.dentry_ttl);
}

void
fbr_cmd_fs_test_release_all(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(cmd->param_count > 1, "Too many params");

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	int release_root_inode = 0;

	if (cmd->param_count == 1 && !strcmp(cmd->params[0].value, "1")) {
		release_root_inode = 1;
	}

	fbr_fs_release_all(fs, release_root_inode);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs root released (release_root_inode=%d)",
		release_root_inode);
}

void
fbr_cmd_fs_test_lru_purge(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 1);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	long value = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(value < 0, "lru value must be positive");

	size_t lru_max = (size_t)value;

	fbr_dindex_lru_purge(fs, lru_max);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs lru purged (lru_max=%zu)", lru_max);
}

void
fbr_cmd_fs_test_assert_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_test_ASSERT(root, "root is missing");
	fbr_directory_ok(root);
	fbr_test_ASSERT(root->state == FBR_DIRSTATE_OK, "bad root state %d", root->state);

	fbr_dindex_release(fs, &root);
}

void
fbr_test_fs_stats(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

#define _FS_TEST_STAT_PRINT(name)	\
	fbr_test_logs("fs.stats." #name ": %lu", fs->stats.name)

	_FS_TEST_STAT_PRINT(directories);
	_FS_TEST_STAT_PRINT(directories_dindex);
	_FS_TEST_STAT_PRINT(directories_total);
	_FS_TEST_STAT_PRINT(directory_refs);
	_FS_TEST_STAT_PRINT(files);
	_FS_TEST_STAT_PRINT(files_inodes);
	_FS_TEST_STAT_PRINT(files_total);
	_FS_TEST_STAT_PRINT(file_refs);
	_FS_TEST_STAT_PRINT(requests_active);
	_FS_TEST_STAT_PRINT(requests_alloc);
	_FS_TEST_STAT_PRINT(requests_freed);
	_FS_TEST_STAT_PRINT(requests_recycled);
	_FS_TEST_STAT_PRINT(requests_pooled);
	_FS_TEST_STAT_PRINT(read_bytes);
	_FS_TEST_STAT_PRINT(write_bytes);
	_FS_TEST_STAT_PRINT(appends);
	_FS_TEST_STAT_PRINT(flushes);
	_FS_TEST_STAT_PRINT(flush_errors);
	_FS_TEST_STAT_PRINT(flush_conflicts);
	_FS_TEST_STAT_PRINT(merges);
	_FS_TEST_STAT_PRINT(wbuffers);
	_FS_TEST_STAT_PRINT(chunk_slabs);
	_FS_TEST_STAT_PRINT(file_ptr_slabs);
	_FS_TEST_STAT_PRINT(buffers);
}

void
fbr_cmd_fs_test_stats(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_test_fs_stats(fs);
}

#define _FS_TEST_STAT(name)							\
char *										\
fbr_var_fs_test_stat_##name(struct fbr_test_context *ctx)			\
{										\
	struct fbr_test_fuse *test_fuse = ctx->test_fuse;			\
	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);		\
	fbr_fuse_mounted(fuse_ctx);						\
	struct fbr_fs *fs = fuse_ctx->fs;					\
	fbr_fs_ok(fs);								\
										\
	fbr_bprintf(test_fuse->stat_str, "%lu",	fs->stats.name);		\
	return test_fuse->stat_str;						\
}

_FS_TEST_STAT(directories)
_FS_TEST_STAT(directories_dindex)
_FS_TEST_STAT(directories_total)
_FS_TEST_STAT(directory_refs)
_FS_TEST_STAT(files)
_FS_TEST_STAT(files_inodes)
_FS_TEST_STAT(files_total)
_FS_TEST_STAT(file_refs)
_FS_TEST_STAT(requests_alloc)
_FS_TEST_STAT(requests_freed)
_FS_TEST_STAT(requests_recycled)
_FS_TEST_STAT(read_bytes)
_FS_TEST_STAT(write_bytes)
_FS_TEST_STAT(appends)
_FS_TEST_STAT(flushes)

static void
_test_fs_inodes_debug_print(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_fullpath_name fullpath;
	const char *fullname = fbr_path_get_full(&file->path, &fullpath);

	fbr_test_logs("INODES debug: inode: %lu type: %s parent: %lu refcount: %u+%u path: %s",
		file->inode,
		fbr_file_is_dir(file) ? "dir" : fbr_file_is_file(file) ? "file" : "other",
		file->parent_inode,
		file->refcounts.dindex, file->refcounts.inode,
		fullname);
}

void
fbr_test_fs_inodes_debug(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	fbr_inodes_debug(fs, _test_fs_inodes_debug_print);

	fbr_test_logs("debug inodes done");
}


static void
_test_fs_dindex_debug_print(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);

	fbr_test_logs("DINDEX debug: inode: %lu refcount: %u+%u+%u files: %zu path: '%s'",
		directory->inode,
		directory->refcounts.in_dindex,
			directory->refcounts.in_lru,
			directory->refcounts.fs,
		directory->file_count,
		dirname.name);
}

void
fbr_test_fs_dindex_debug(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	fbr_dindex_debug(fs, _test_fs_dindex_debug_print);

	fbr_test_logs("debug dindex done");
}

void
fbr_cmd_fs_test_debug(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);
}

struct fbr_fs *
fbr_test_fs_alloc(void)
{
	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	return fs;
}

size_t
fbr_test_fs_read(struct fbr_fs *fs, struct fbr_file *file, size_t offset, char *buffer,
    size_t buffer_len)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(buffer);
	assert(buffer_len);

	struct fbr_fio *fio = fbr_fio_alloc(fs, file, 1);

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, offset, buffer_len);
	if (!vector) {
		fbr_fio_release(fs, fio);
		return 0;
	}

	struct fuse_bufvec *bufvec = vector->bufvec;
	size_t bytes = 0;
	for (size_t i = 0; i < bufvec->count; i++) {
		struct fuse_buf *buf = &bufvec->buf[i];
		memcpy(buffer + bytes, buf->mem, buf->size);
		bytes += buf->size;
		assert(bytes <= buffer_len);
	}

	fbr_fio_vector_free(fs, fio, vector);
	fbr_fio_release(fs, fio);

	return bytes;
}
