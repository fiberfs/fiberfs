/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static DIR *_TEST_DIR;
static int _TEST_FD = -1;

static int _TEST_FS_ALLOW_CRASH;

static void
_test_fs_init_contents(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);

	fbr_test_logs("** INIT LOADING inode: %lu directory: '%.*s':%zu",
		directory->inode, (int)dirname.len, dirname.name, dirname.len);

	size_t depth = 0;

	while(dirname.len) {
		fbr_path_name_parent(&dirname, &dirname);
		depth++;
		assert(depth < 1000);
	}

	char name[128];
	struct fbr_path_name filename;
	struct fbr_file *file;
	int ret;

	if (!depth) {
		ret = snprintf(name, sizeof(name), "fiber_zero");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		file->mode = S_IFREG | 0444;
		file->size = 1025 * 125;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;

		ret = snprintf(name, sizeof(name), "fiber_zero1");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		file->mode = S_IFREG | 0444;
		file->size = 500;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;

		ret = snprintf(name, sizeof(name), "fiber_big");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		fbr_id_t id = fbr_id_gen();

		size_t s = 1024 * 512;

		fbr_body_chunk_add(fs, file, id, s * 0, s);
		fbr_body_chunk_add(fs, file, id, 10000, 100000);
		fbr_body_chunk_add(fs, file, id, s * 0, s + 100);
		fbr_body_chunk_add(fs, file, id, s * 1, s);

		file->mode = S_IFREG | 0444;
		file->size = 1024 * 1024;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;

		ret = snprintf(name, sizeof(name), "fiber_small");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		id = fbr_id_gen();

		file->mode = S_IFREG | 0444;
		file->size = 101;
		file->generation = fbr_id_gen();

		fbr_body_chunk_add(fs, file, id, 0, 101);

		file->state = FBR_FILE_OK;
	}

	for (size_t i = 0; i < 4; i++) {
		mode_t fmode = S_IFREG | 0444;

		ret = snprintf(name, sizeof(name), "fiber_%zu%zu", depth, i + 1);
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);

		size_t chunks = (i + 1) * depth;
		file->generation = fbr_id_gen();
		file->mode = fmode;

		fbr_id_t id = fbr_id_gen();
		size_t offset = 0;
		for (size_t i = 0; i < chunks; i++) {
			if (!offset) {
				// even length will fail checksum
				fbr_body_chunk_add(fs, file, id, 0, 11);
				fbr_body_chunk_add(fs, file, id, 0, 10);
				fbr_body_chunk_add(fs, file, id, 500, 607);
				fbr_body_chunk_add(fs, file, id, 600, 500);
				fbr_body_chunk_add(fs, file, id, 0, 601);
				fbr_body_chunk_add(fs, file, id, 590, 551);
			} else {
				fbr_body_chunk_add(fs, file, id, offset, 1001);
			}
			offset += 1001;
		}

		file->size = chunks * 1001;
		assert(offset == file->size);

		file->state = FBR_FILE_OK;
	}

	for (size_t i = 0; i < 4; i++) {
		if (depth > 4) {
			break;
		}

		mode_t fmode = S_IFDIR | 0555;

		ret = snprintf(name, sizeof(name), "fiber_dir%zu%zu", depth, i + 1);
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);

		file->mode = fmode;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;
	}

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
}

static struct fbr_directory *
_test_fs_init_directory(struct fbr_fs *fs, const struct fbr_path_name *dirname, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(dirname);
	assert(inode);

	struct fbr_directory *directory = NULL;

	if (inode == FBR_INODE_ROOT) {
		assert_zero(dirname->len);
		directory = fbr_directory_root_alloc(fs);
	} else {
		assert(dirname->len);
		directory = fbr_directory_alloc(fs, dirname, inode);
	}

	if (directory->state == FBR_DIRSTATE_LOADING) {
		_test_fs_init_contents(fs, directory);
	} else if (directory->state == FBR_DIRSTATE_ERROR) {
		fbr_test_logs("** INIT ERROR inode: %lu directory: '%.*s':%zu",
			directory->inode, (int)dirname->len, dirname->name, dirname->len);
		fbr_dindex_release(fs, &directory);
		return NULL;
	} else {
		assert(directory->state == FBR_DIRSTATE_OK);
		fbr_test_logs("** INIT OK inode: %lu directory: '%.*s':%zu",
			directory->inode, (int)dirname->len, dirname->name, dirname->len);
	}

	fbr_ASSERT(directory->state == FBR_DIRSTATE_OK, "directory->state: %d", directory->state);

	return directory;
}

static void
_test_fs_chunk_gen(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	char buf[PATH_MAX];
	const char *fullpath = fbr_path_get_full(&file->path, NULL, buf, sizeof(buf));

	fbr_test_logs("** FETCH chunk: offset: %zu length: %zu splice: %d path: %s",
		chunk->offset, chunk->length, chunk->fd_splice_ok, fullpath);

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	size_t counter = chunk->offset;

	if (chunk->length % 2 == 0 && chunk->length < 1024) {
		counter++;
	}

	for (size_t i = 0; i < chunk->length; i++) {
		chunk->data[i] = (counter % 10) + '0';
		counter++;
	}

	chunk->state = FBR_CHUNK_READY;

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, chunk->length);
}

static const struct fbr_store_callbacks _TEST_FS_STORE_CALLBACKS = {
	.directory_load_f = _test_fs_init_directory,
	.chunk_read_f = _test_fs_chunk_gen
};

static void
_test_fs_fuse_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	ctx->fs->logger = fbr_test_fs_logger;

	conn->want |= FUSE_CAP_SPLICE_WRITE;
	conn->want |= FUSE_CAP_SPLICE_MOVE;

	fbr_fs_set_store(ctx->fs, &_TEST_FS_STORE_CALLBACKS);

	fbr_test_random_seed();
}

static void
_test_fs_fuse_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	fbr_request_ok(request);

	if (_TEST_FS_ALLOW_CRASH && !strcmp(name, "__CRASH")) {
		fbr_test_logs("LOOKUP req: %lu name: %s", request->id, name);
		fbr_ABORT("__CRASH triggered!");
	}

	fbr_ops_lookup(request, parent, name);
}

static void
_test_fs_fuse_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	fbr_request_ok(request);

	if (random() % 2 == 0) {
		size = (random() % 256) + 50;
		fbr_test_logs("READDIR size: %zu", size);
	}

	fbr_ops_readdir(request, ino, size, off, fi);
}

static void
_test_fs_fuse_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_ok(request);

	if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		fbr_test_logs("** OPEN detected write");
		fbr_fuse_reply_err(request, EROFS);
		return;
	}

	fbr_ops_open(request, ino, fi);
}

static const struct fbr_fuse_callbacks _TEST_FS_FUSE_CALLBACKS = {
	.init = _test_fs_fuse_init,

	.getattr = fbr_ops_getattr,
	.lookup = _test_fs_fuse_lookup,

	.opendir = fbr_ops_opendir,
	.readdir = _test_fs_fuse_readdir,
	.releasedir = fbr_ops_releasedir,

	.open = _test_fs_fuse_open,
	.read = fbr_ops_read,
	.release = fbr_ops_release,

	.forget = fbr_ops_forget,
	.forget_multi = fbr_ops_forget_multi
};

void
fbr_cmd_fs_test_fuse_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_FUSE_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fs->logger = fbr_test_fs_logger;
}

void
fbr_cmd_fs_test_fuse_init_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = _test_fs_init_directory(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT);
	fbr_dindex_release(fs, &root);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs root initialized");
}

void
fbr_cmd_fs_test_allow_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_TEST_FS_ALLOW_CRASH = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs allow crash %d", _TEST_FS_ALLOW_CRASH);
}

void
fbr_cmd__fs_test_take_dir(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_ASSERT(_TEST_DIR == NULL, "_TEST_DIR exists");

	char *dirname = cmd->params[0].value;

	_TEST_DIR = opendir(dirname);
	fbr_test_ASSERT(_TEST_DIR, "opendir failed for %s", dirname);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "dir handle aquired %s", dirname);
}

void
fbr_cmd__fs_test_release_dir(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_ASSERT(_TEST_DIR, "_TEST_DIR invalid");

	int ret = closedir(_TEST_DIR);
	fbr_test_ERROR(ret, "closedir failed %d", ret);

	_TEST_DIR = NULL;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "dir handle released");
}

void
fbr_cmd__fs_test_take_file(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_ASSERT(_TEST_FD == -1, "_TEST_FD exists");

	char *filename = cmd->params[0].value;

	_TEST_FD = open(filename, O_RDONLY);
	fbr_test_ASSERT(_TEST_FD >= 0, "open failed for %s", filename);

	uint8_t buf[100];
	ssize_t bytes = read(_TEST_FD, buf, sizeof(buf));
	fbr_test_ASSERT(bytes >= 0, "read error");

	for (ssize_t i = 0; i < bytes; i++) {
		fbr_test_ASSERT(buf[i] == '\0', "bad bytes in read");
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fd handle aquired %s (%zd)", filename, bytes);
}

void
fbr_cmd__fs_test_release_file(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_ASSERT(_TEST_FD >= 0, "_TEST_FD invalid");

	ssize_t bytes, total = 0;

	do {
		uint8_t buf[100];
		bytes = read(_TEST_FD, buf, sizeof(buf));
		fbr_test_ASSERT(bytes >= 0, "read error");

		for (ssize_t i = 0; i < bytes; i++) {
			fbr_test_ASSERT(buf[i] == '\0', "bad bytes in read");
		}

		total += bytes;
	} while (bytes > 0);

	int ret = close(_TEST_FD);
	fbr_test_ERROR(ret, "closedir failed %d", ret);

	_TEST_FD = -1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fd handle released (%zd)", total);
}
