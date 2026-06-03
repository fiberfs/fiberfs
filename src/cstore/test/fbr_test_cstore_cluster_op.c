/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "config/test/fbr_test_config_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

#define _OP_THREADS	4

static struct fbr_cstore *_CSTORE_C0_SHARED;
static struct fbr_cstore *_CSTORE_C1_S3;
static int _MKDIR_SUBDIR;
static int _MKDIR_APPEND;
static size_t _THREADS;
static size_t _MKDIR_SUCCESS;
static size_t _MKDIR_EXIST;
static size_t _MKDIR_NOTSYNC;
static size_t _MKDIR_ERROR;
static size_t _MKDIR_MISSING;
static size_t _APPEND_OPEN;
static size_t _APPEND_CREATE;
static size_t _CONFLICTS;
static size_t _APPEND_COUNT;

static void
_assert_fs(struct fbr_fs *fs, int print)
{
	fbr_fs_ok(fs);

	fbr_fs_release_all(fs, 1);

	if (print) {
		fbr_test_fs_stats(fs);
		fbr_test_fs_dindex_debug(fs);
		fbr_test_fs_inodes_debug(fs);
	} else {
		fbr_test_fs_wait(fs);
	}

	fbr_test_cstore_wait(fs->cstore);

	assert_zero(fs->stats.directories);
	assert_zero(fs->stats.directories_dindex);
	assert_zero(fs->stats.directory_refs);
	assert_zero(fs->stats.files);
	assert_zero(fs->stats.files_inodes);
	assert_zero(fs->stats.file_refs);
}

static size_t
_write_count(char *buffer, size_t buffer_len)
{
	size_t count = fbr_atomic_add(&_APPEND_COUNT, 1);
	size_t count_len = fbr_snprintf(buffer, buffer_len, "%zu ", count);
	return count_len;
}

void
_op_mkdir_append(struct fbr_fs *fs, struct fbr_path_name *parent_path, fbr_inode_t parent_inode)
{
	fbr_fs_ok(fs);
	assert(parent_path);
	assert(parent_inode);

	fbr_rlog(FBR_LOG_TEST, "OP_append %s:%lu", parent_path->name, parent_inode);

	struct fbr_directory *directory = fbr_dindex_take(fs, parent_path, 0);
	if (!directory) {
		directory = fbr_directory_load(fs, parent_path, parent_inode, 0);
	}
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, "append");

	struct fuse_file_info fi;

	struct fbr_request *request = fbr_request_get();
	fbr_request_ok(request);
	request->error = 0;

	struct fbr_file *file = fbr_directory_find_file(directory, filename.name, filename.length);
	if (file) {
		fbr_file_ok(file);
		assert(file->state == FBR_FILE_OK);

		fbr_inode_add(fs, file);

		fbr_zero(&fi);
		fi.flags = O_WRONLY | O_APPEND;

		fbr_ops_open(request, file->inode, &fi);
		assert_zero(request->error);

		struct fbr_fio *fio = fbr_fh_fio(fi.fh);
		fbr_file_ok(fio->file);
		assert(fio->file == file);

		char buffer[32];
		size_t buffer_len = _write_count(buffer, sizeof(buffer));

		fbr_ops_write(request, fio->file->inode, buffer, buffer_len, 0, &fi);
		assert_zero(request->error);

		fbr_ops_release(request, file->inode, &fi);
		assert_zero(request->error);

		fbr_inode_release(fs, &file);

		fbr_stat_add(&_APPEND_OPEN);
	} else {
		fbr_zero(&fi);
		fi.flags = O_CREAT | O_WRONLY | O_APPEND;

		fbr_ops_create(request, parent_inode, filename.name, S_IFREG, &fi);
		assert_zero(request->error);

		struct fbr_fio *fio = fbr_fh_fio(fi.fh);
		fbr_file_ok(fio->file);

		char buffer[32];
		size_t buffer_len = _write_count(buffer, sizeof(buffer));

		fbr_ops_write(request, fio->file->inode, buffer, buffer_len, 0, &fi);
		assert_zero(request->error);

		fbr_ops_release(request, fio->file->inode, &fi);
		assert_zero(request->error);

		fbr_stat_add(&_APPEND_CREATE);
	}

	fbr_dindex_release(fs, &directory);
}

void
_op_mkdir_subdir(struct fbr_fs *fs, struct fbr_path_name *parent_path, fbr_inode_t parent_inode)
{
	fbr_fs_ok(fs);
	assert(parent_path);
	assert(parent_inode);

	fbr_rlog(FBR_LOG_TEST, "OP_subdir %s:%lu", parent_path->name, parent_inode);

	struct fbr_directory *parent = fbr_directory_load(fs, parent_path, parent_inode, 0);
	fbr_directory_ok(parent);
	assert(parent->state == FBR_DIRSTATE_OK);

	long subdir_id = fbr_test_gen_random(1, _OP_THREADS);
	char subdir_name[32];
	fbr_bprintf(subdir_name, "subdir_%zu", subdir_id);

	fbr_rlog(FBR_LOG_TEST, "OP_subdir mkdir(%s/%s)", parent_path->name, subdir_name);

	struct fbr_request *request = fbr_request_get();
	fbr_request_ok(request);
	request->error = 0;

	fbr_ops_mkdir(request, parent_inode, subdir_name, 0);

	fbr_rlog(FBR_LOG_TEST, "OP_subdir mkdir() ret: %d", request->error);

	if (request->error == EEXIST) {
		fbr_stat_add(&_MKDIR_EXIST);
	} else if (request->error == ENOTDIR) {
		fbr_stat_add(&_MKDIR_NOTSYNC);
	} else if (request->error) {
		fbr_stat_add(&_MKDIR_ERROR);
	} else {
		fbr_stat_add(&_MKDIR_SUCCESS);
	}

	fbr_dindex_release(fs, &parent);
}

static void *
_op_mkdir_thread(void *arg)
{
	(void)arg;

	size_t id = fbr_atomic_add(&_THREADS, 1);

	fbr_test_logs("*** op thread %zu running", id);

	struct fbr_fs *fs = fbr_test_fs_mock(NULL);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_cstore_ok(fs->cstore);
	assert(fs->cstore_managed);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C1_S3, FBR_CSTORE_ROUTE_S3);

	if (!(random() % 4) && 0) {
		fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C0_SHARED, FBR_CSTORE_ROUTE_CLUSTER);
	} else {
		fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C0_SHARED, FBR_CSTORE_ROUTE_CDN);
	}

	struct fbr_test_context *test_ctx = fbr_test_get_ctx();
	struct fbr_test_cstore *tcstore = fbr_test_tcstore_match(test_ctx, fs->cstore);

	while (_THREADS < _OP_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_THREADS == _OP_THREADS);

	size_t dir_count = _OP_THREADS;
	if (_MKDIR_SUBDIR) {
		dir_count += _OP_THREADS * _OP_THREADS;
	}

	while (_MKDIR_SUCCESS < dir_count) {
		struct fbr_request *request = fbr_test_request_mock();
		fbr_fuse_detached(request->fuse_ctx);
		request->fs = fs;
		fbr_request_valid(request);
		assert_zero(request->error);

		fbr_rlog(FBR_LOG_TEST, "OP_thread %zu cstore: %s", id, tcstore->prefix);

		struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
		if (!root) {
			root = fbr_directory_load(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0);
		}
		fbr_directory_ok(root);
		assert(root->state == FBR_DIRSTATE_OK);

		long dir_id = fbr_test_gen_random(1, _OP_THREADS);
		char dirname[32];
		fbr_bprintf(dirname, "directory_%zu", dir_id);
		struct fbr_path_name dirpath;
		fbr_path_name_init(&dirpath, dirname);

		fbr_rlog(FBR_LOG_TEST, "OP_thread %zu calling mkdir(%s)", id, dirname);

		fbr_ops_mkdir(request, root->inode, dirname, 0);

		fbr_rlog(FBR_LOG_TEST, "OP_thread %zu mkdir() ret: %d", id, request->error);

		if (request->error == EEXIST) {
			fbr_stat_add(&_MKDIR_EXIST);
		} else if (request->error == ENOTDIR) {
			fbr_stat_add(&_MKDIR_NOTSYNC);
		} else if (request->error) {
			fbr_stat_add(&_MKDIR_ERROR);
		} else {
			if (_MKDIR_APPEND) {
				fbr_sleep_ms(5);
			}
			fbr_stat_add(&_MKDIR_SUCCESS);
		}

		fbr_dindex_release(fs, &root);

		if (!_MKDIR_SUBDIR && !_MKDIR_APPEND) {
			fbr_request_free(request);

			if (_MKDIR_EXIST > 16) {
				fbr_test_sleep_ms(10);
			}

			continue;
		}

		root = fbr_directory_load(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0);
		fbr_directory_ok(root);
		assert(root->state == FBR_DIRSTATE_OK);

		struct fbr_file *file = fbr_directory_find_file(root, dirpath.name, dirpath.length);
		if (!file) {
			fbr_dindex_release(fs, &root);
			fbr_request_free(request);
			fbr_stat_add(&_MKDIR_MISSING);
			continue;
		}
		fbr_file_ok(file);
		assert(file->state == FBR_FILE_OK);
		assert(file->mode & S_IFDIR);

		fbr_inode_add(fs, file);

		fbr_dindex_release(fs, &root);

		if (_MKDIR_SUBDIR) {
			_op_mkdir_subdir(fs, &dirpath, file->inode);
		} else {
			_op_mkdir_append(fs, &dirpath, file->inode);
		}

		fbr_inode_release(fs, &file);

		fbr_request_free(request);

		if (_MKDIR_EXIST > 100) {
			fbr_test_sleep_ms(1);
		}
	}

	fbr_stat_add_count(&_CONFLICTS, fs->stats.flush_conflicts);

	fbr_test_cstore_wait(fs->cstore);
	assert_zero(fs->cstore->stats.http_500);
	_assert_fs(fs, 0);
	fbr_fs_free(fs);

	return NULL;
}

static void
_debug_cstores(void)
{
	fbr_test_logs("CSTORE_DEBUG OBJECT: cstore_c0_shared");
	fbr_test_cstore_debug(_CSTORE_C0_SHARED);
	fbr_test_logs("CSTORE_DEBUG OBJECT: cstore_c1_s3");
	fbr_test_cstore_debug(_CSTORE_C1_S3);
}

static void
_validate_append(struct fbr_fs *fs, struct fbr_directory *subdir, char *append_counts)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(subdir);
	assert(subdir->state == FBR_DIRSTATE_OK);
	assert(append_counts);
	assert(_MKDIR_APPEND);

	struct fbr_file *file = fbr_directory_find_file(subdir, "append", 6);
	if (!file) {
		return;
	}

	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->mode & S_IFREG);

	struct fbr_path_name dirname;
	fbr_directory_name(subdir, &dirname);

	fbr_test_logs("  append found subdir: %s (%lu,%lu) inode: %lu,%lu size: %zu bytes "
		"refs: %u+%u",
		dirname.name, subdir->inode, subdir->generation,
		file->inode, file->generation, file->size,
		file->refcounts.dindex, file->refcounts.inode);

	char buffer[4096];
	assert(sizeof(buffer) > file->size);
	size_t bytes = fbr_test_fs_read(fs, file, 0, buffer, sizeof(buffer));
	assert(bytes == file->size);
	buffer[file->size] = '\0';

	char *check_pos = buffer;
	while (*check_pos) {
		char *end = NULL;
		long value = strtol(check_pos, &end, 10);
		assert(end && *end == ' ');
		assert(value > 0 && (size_t)value <= _APPEND_COUNT);
		check_pos = end + 1;
		append_counts[value]++;
	}

	fbr_test_logs("  append done %s refs: %u+%u", dirname.name,
		file->refcounts.dindex, file->refcounts.inode);
}

static void
_validate_subdir(struct fbr_fs *fs, struct fbr_directory *subdir)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(subdir);
	assert(subdir->state == FBR_DIRSTATE_OK);

	for (size_t i = 1; i < _OP_THREADS; i++) {
		char subdir_name[32];
		size_t len = fbr_bprintf(subdir_name, "subdir_%zu", i);

		struct fbr_file *file = fbr_directory_find_file(subdir, subdir_name, len);
		fbr_ASSERT(file, "ERROR directory missing: %s", subdir_name);
		fbr_file_ok(file);
		assert(file->state == FBR_FILE_OK);
		assert(file->mode | S_IFDIR);
	}

	assert(subdir->file_count == _OP_THREADS);

	fbr_test_logs("  subdir passed all directories found");
}

static void
_validate_root(struct fbr_fs *fs, struct fbr_directory *root)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	char *append_counts = NULL;
	if (_APPEND_COUNT) {
		append_counts = calloc(1, _APPEND_COUNT + 1);
		assert(append_counts);
	}

	for (size_t i = 1; i <= _OP_THREADS; i++) {
		char dirname[32];
		size_t len = fbr_bprintf(dirname, "directory_%zu", i);

		struct fbr_file *file = fbr_directory_find_file(root, dirname, len);
		fbr_ASSERT(file, "ERROR directory missing: %s", dirname);
		fbr_file_ok(file);
		assert(file->state == FBR_FILE_OK);
		assert(file->mode | S_IFDIR);

		if (!_MKDIR_SUBDIR && !_MKDIR_APPEND) {
			continue;
		}

		struct fbr_path_name subdir_path;
		fbr_path_name_init(&subdir_path, dirname);

		fbr_inode_add(fs, file);

		struct fbr_directory *subdir = fbr_directory_load(fs, &subdir_path, file->inode, 0);
		fbr_directory_ok(subdir);
		assert(subdir->state == FBR_DIRSTATE_OK);

		if (_MKDIR_SUBDIR) {
			_validate_subdir(fs, subdir);
		} else if (append_counts) {
			_validate_append(fs, subdir, append_counts);
		}

		fbr_inode_release(fs, &file);
		fbr_dindex_release(fs, &subdir);
	}

	assert(root->file_count == _OP_THREADS);

	if (_APPEND_COUNT) {
		for (size_t i = 1; i <= _APPEND_COUNT; i++) {
			fbr_ASSERT(append_counts[i] == 1, "append missing: %zu", i);
		}
		fbr_test_logs("  append all counts found: %zu", _APPEND_COUNT);
		free(append_counts);
	}

	fbr_test_logs("root passed all directories found");
}

static void
_cluster_mkdir(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	assert(_MKDIR_SUBDIR + _MKDIR_APPEND <= 1);

	fbr_test_random_seed();

	fbr_test_conf_add("LOG_ALWAYS_FLUSH", "true");
	fbr_test_conf_add("ASYNC_WRITE", "false");
	fbr_test_conf_add("CSTORE_SERVER", "true");
	fbr_test_conf_add("CSTORE_SERVER_ADDRESS", "127.0.0.1");
	fbr_test_conf_add("CSTORE_SERVER_PORT", "0");
	fbr_test_conf_add("ALLOW_CDN_PUT", "true");
	fbr_test_conf_add("ALLOW_CDN_DELETE", "true");

	fbr_test_fuse_mock(ctx);

	_CSTORE_C0_SHARED = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(_CSTORE_C0_SHARED);

	_CSTORE_C1_S3 = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(_CSTORE_C1_S3);
	fbr_test_cstore_s3_mock(_CSTORE_C1_S3, NULL, "NYC", "AccessKEY", "SECRET!@#");

	fbr_test_cstore_backend_add(_CSTORE_C0_SHARED, _CSTORE_C1_S3, FBR_CSTORE_ROUTE_S3);

	assert(fbr_test_cstore_get(ctx, 0) == _CSTORE_C0_SHARED);
	assert(fbr_test_cstore_get(ctx, 1) == _CSTORE_C1_S3);
	assert(fbr_test_cstore_count(ctx) == 2);

	fbr_test_conf_add("CSTORE_SERVER", NULL);

	struct fbr_fs *fs = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C0_SHARED, FBR_CSTORE_ROUTE_CDN);
	fbr_test_cstore_backend_add(fs->cstore, _CSTORE_C1_S3, FBR_CSTORE_ROUTE_S3);

	fbr_test_fs_root_alloc(fs);

	fbr_test_sleep_ms(20);

	fbr_test_fs_wait(fs);
	_debug_cstores();

	assert(_CSTORE_C0_SHARED->entries == 2);
	assert(_CSTORE_C0_SHARED->stats.wr_indexes == 1);
	assert(_CSTORE_C0_SHARED->stats.wr_roots == 1);
	assert(_CSTORE_C1_S3->entries == 2);
	assert(_CSTORE_C1_S3->stats.wr_indexes == 1);
	assert(_CSTORE_C1_S3->stats.wr_roots == 1);

	assert(_OP_THREADS > 0);
	assert_zero(_THREADS);
	assert_zero(_MKDIR_SUCCESS);
	assert_zero(_MKDIR_EXIST);
	assert_zero(_MKDIR_NOTSYNC);
	assert_zero(_MKDIR_ERROR);

	fbr_test_logs("*** starting %d threads", _OP_THREADS);

	pthread_t threads[_OP_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _op_mkdir_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_THREADS == _OP_THREADS);

	fbr_test_sleep_ms(100);

	fbr_fs_release_all(fs, 0);
	fbr_cstore_clear(fs->cstore);
	fbr_test_fs_wait(fs);
	assert_zero(fs->stats.directories);
	assert(fs->stats.files == 1);

	struct fbr_directory *root = fbr_directory_load(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	fbr_test_fs_wait(fs);
	assert(fs->stats.directories == 1);
	assert(root->file_count == 4);
	assert(fs->stats.files == 5);

	struct fbr_directory *root_d3 = fbr_directory_load(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 1);
	fbr_directory_ok(root_d3);
	assert(root_d3->state == FBR_DIRSTATE_OK);

	fbr_test_fs_wait(fs);
	assert(fs->stats.directories == 1);
	assert(root_d3->file_count == 4);
	assert(fs->stats.files == 5);

	fbr_test_sleep_ms(20);

	fbr_test_logs("*** loading root directly from _CSTORE_C1_S3");

	struct fbr_fs *fs_s3 = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs_s3);
	fbr_test_cstore_bind(fs_s3, 1);
	assert(fs_s3->cstore == _CSTORE_C1_S3);
	fbr_fs_set_store(fs_s3, FBR_CSTORE_DEFAULT_CALLBACKS);

	struct fbr_directory *root_s3 = fbr_directory_load(fs_s3, FBR_DIRNAME_ROOT,
		FBR_INODE_ROOT, 0);
	fbr_directory_ok(root_s3);
	assert(root_s3->state == FBR_DIRSTATE_OK);

	_validate_root(fs, root);
	_validate_root(fs, root_d3);
	_validate_root(fs_s3, root_s3);

	assert(root->generation == root_d3->generation);
	assert(root->generation == root_s3->generation);
	assert(root->version == root_d3->version);
	assert(root->version == root_s3->version);

	fbr_dindex_release(fs, &root);
	fbr_dindex_release(fs, &root_d3);
	fbr_dindex_release(fs_s3, &root_s3);

	fbr_test_sleep_ms(20);

	_debug_cstores();

	fbr_test_logs("FLUSH_CONFLICTS: %zu", _CONFLICTS);
	fbr_test_logs("MKDIR SUCCESS: %zu", _MKDIR_SUCCESS);
	fbr_test_logs("MKDIR EXIST: %zu", _MKDIR_EXIST);
	fbr_test_logs("MKDIR NOT SYNC: %zu", _MKDIR_NOTSYNC);
	fbr_test_logs("MKDIR MISSING: %zu", _MKDIR_MISSING);
	fbr_test_logs("MKDIR ERROR: %zu", _MKDIR_ERROR);

	if (_MKDIR_APPEND) {
		fbr_test_logs("APPEND OPEN: %zu", _APPEND_OPEN);
		fbr_test_logs("APPEND CREATE: %zu", _APPEND_CREATE);
		fbr_test_logs("APPEND COUNT: %zu", _APPEND_COUNT);
	}

	size_t dir_count = _OP_THREADS;
	if (_MKDIR_SUBDIR) {
		dir_count += _OP_THREADS * _OP_THREADS;
	}

	assert(fbr_test_cstore_count(ctx) == 2 + 1 + _OP_THREADS);
	if (!_MKDIR_APPEND) {
		assert(_CSTORE_C1_S3->entries == 2 + (dir_count * 2));
		assert_zero(_CSTORE_C1_S3->stats.wr_chunks);
	} else {
		assert(_CSTORE_C1_S3->stats.wr_chunks == _APPEND_COUNT);
	}
	assert(_CSTORE_C1_S3->stats.wr_indexes == 1 + dir_count);
	assert(_CSTORE_C1_S3->stats.wr_roots == 1 + dir_count);

	assert(_MKDIR_SUCCESS == dir_count);
	assert_zero(_MKDIR_ERROR);

	assert_zero(_CSTORE_C1_S3->stats.http_500);
	assert_zero(_CSTORE_C0_SHARED->stats.http_500);

	_assert_fs(fs, 1);
	_assert_fs(fs_s3, 0);

	fbr_request_pool_shutdown();
	fbr_fs_free(fs);
	fbr_fs_free(fs_s3);

	_CSTORE_C0_SHARED = NULL;
	_CSTORE_C1_S3 = NULL;

	fbr_test_logs("cstore_cluster_mkdir done");
}

void
fbr_cmd_cstore_cluster_mkdir(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	assert_zero(_MKDIR_SUBDIR);

	fbr_test_conf_add("LOG_SIZE", "1000000");

	_cluster_mkdir(ctx);
}

void
fbr_cmd_cstore_cluster_subdir(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_MKDIR_SUBDIR = 1;

	fbr_test_conf_add("LOG_SIZE", "5000000");

	_cluster_mkdir(ctx);
}

void
fbr_cmd_cstore_cluster_append(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	assert_zero(_MKDIR_SUBDIR);

	_MKDIR_APPEND = 1;

	fbr_test_conf_add("LOG_SIZE", "5000000");

	_cluster_mkdir(ctx);
}
