/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse.h"

#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

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
	_FS_TEST_STAT_PRINT(read_bytes);
	_FS_TEST_STAT_PRINT(write_bytes);
	_FS_TEST_STAT_PRINT(appends);
	_FS_TEST_STAT_PRINT(flushes);
	_FS_TEST_STAT_PRINT(flush_errors);
	_FS_TEST_STAT_PRINT(flush_conflicts);
	_FS_TEST_STAT_PRINT(merges);
	_FS_TEST_STAT_PRINT(lru_loops);
	_FS_TEST_STAT_PRINT(lru_attempts);
	_FS_TEST_STAT_PRINT(wbuffers);
	_FS_TEST_STAT_PRINT(chunk_slabs);
	_FS_TEST_STAT_PRINT(file_ptr_slabs);
	_FS_TEST_STAT_PRINT(buffers);

	struct fbr_request_stats *req_stats = fbr_request_get_stats();
	assert(req_stats);
	fbr_test_logs("request.stats.requests_active: %lu", req_stats->requests_active);
	fbr_test_logs("request.stats.requests_alloc: %lu", req_stats->requests_alloc);
	fbr_test_logs("request.stats.requests_freed: %lu", req_stats->requests_freed);
	fbr_test_logs("request.stats.requests_pooled: %lu", req_stats->requests_pooled);
	fbr_test_logs("request.stats.requests_recycled: %lu", req_stats->requests_recycled);

	fbr_test_logs("fs.config.reader.updates: %lu (%lu,%lu)",
		fs->config.reader.updates, fs->config.reader.attempts,
		fs->config.reader.cas_race);
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
const char *									\
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
	assert_zero(fs->fuse_ctx);

	return fs;
}

struct fbr_fs *
fbr_test_fs_mock(struct fbr_test_context *test_ctx)
{
	if (!test_ctx) {
		test_ctx = fbr_test_get_ctx();
	}
	fbr_test_context_ok(test_ctx);

	fbr_test_fuse_mock(test_ctx);

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	fbr_fuse_context_ok(fuse_ctx);
	assert_zero(fuse_ctx->fs);

	struct fbr_fs *fs = fbr_test_fs_alloc();

	return fs;
}

void
fbr_test_fs_root_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);
	assert_zero(root->generation);

	root->generation = 1;

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, root, NULL, NULL, NULL, FBR_FLUSH_NONE);

	int ret = fbr_index_write(fs, &index_data);
	fbr_ASSERT(!ret, "fbr_index_write() root failed: %d", ret);

	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	fbr_index_data_free(&index_data);
	fbr_dindex_release(fs, &root);
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
