/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/operations/fbr_operations.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "config/test/fbr_test_config_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

void
fbr_cmd_rename_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx)
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count >= 2 && cmd->param_count <= 3);
	assert(cmd->params[0].len);
	assert(cmd->params[1].len);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	const char *filename = cmd->params[0].value;
	const char *filename_dest = cmd->params[1].value;

	unsigned int flags = 0;
	if (cmd->param_count >= 3) {
		flags = fbr_test_parse_long(cmd->params[2].value);
	}

	int ret = renameat2(AT_FDCWD, filename, AT_FDCWD, filename_dest, flags);
	fbr_ASSERT(ret, "renameat2(%s,%s,%u) did not fail", filename, filename_dest, flags);

	fbr_test_logs("renameat2(%s,%s,%u) PASSED with failure %s (%d)", filename, filename_dest,
		flags, strerror(errno), ret);
}

static struct fbr_request *
_rename_request(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_request *request = fbr_request_get();
	if (request) {
		assert_zero(request->error);
		fbr_request_free(request);
	}

	request = fbr_test_request_mock();
	fbr_fuse_detached(request->fuse_ctx);
	request->fs = fs;
	fbr_request_valid(request);
	assert_zero(request->error);

	return request;
}

static void
_rename_test(struct fbr_test_context *ctx, int append)
{
	assert_dev(ctx);

	fbr_test_fuse_mock(ctx);
	fbr_test_request_pool_register(ctx);

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_bind_new(fs);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Create root");

	fbr_test_fs_root_alloc(fs);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Create file.1");

	struct fbr_path_name filename1;
	fbr_path_name_init(&filename1, "file.1");
	struct fbr_path_name filename2;
	fbr_path_name_init(&filename2, "file.2");

	struct fbr_request *request = _rename_request(fs);

	struct fbr_directory *root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	struct fuse_file_info fi;
	fbr_zero(&fi);
	fi.flags = O_CREAT | O_WRONLY;

	fbr_ops_create(request, FBR_INODE_ROOT, filename1.name, S_IFREG, &fi);
	assert_zero(request->error);

	struct fbr_fio *fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);

	request = _rename_request(fs);

	fbr_ops_write(request, fio->file->inode, "pre_rename", 10, 0, &fi);
	assert_zero(request->error);

	request = _rename_request(fs);

	fbr_ops_release(request, fio->file->inode, &fi);
	assert_zero(request->error);

	fbr_dindex_release(fs, &root);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Append to file.1 (1)");

	root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	struct fbr_file *file = fbr_directory_find_file(root, filename1.name, filename1.length);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);

	fbr_inode_add(fs, file);
	fbr_dindex_release(fs, &root);

	request = _rename_request(fs);

	fbr_zero(&fi);
	if (append) {
		fi.flags = O_WRONLY | O_APPEND;
	} else {
		fi.flags = O_WRONLY;
	}

	fbr_ops_open(request, file->inode, &fi);
	assert_zero(request->error);

	fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);
	assert(fio->file == file);

	request = _rename_request(fs);

	fbr_ops_write(request, fio->file->inode, " append1", 8, 0, &fi);
	assert_zero(request->error);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Rename file.1 to file.2");

	request = _rename_request(fs);

	fbr_ops_rename(request, FBR_INODE_ROOT, filename1.name, FBR_INODE_ROOT, filename2.name, 0);
	assert_zero(request->error);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Append to file.1 (2)");

	request = _rename_request(fs);

	fbr_ops_write(request, fio->file->inode, " append2", 8, 0, &fi);
	assert_zero(request->error);

	request = _rename_request(fs);

	fbr_ops_release(request, file->inode, &fi);
	assert_zero(request->error);
	fbr_inode_release(fs, &file);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Validate file.2");

	root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert(root->file_count == 1);

	file = fbr_directory_find_file(root, filename2.name, filename2.length);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	if (append) {
		fbr_ASSERT(file->size == 26, "found size: %lu", file->size);
	} else {
		fbr_ASSERT(file->size == 10, "found size: %lu", file->size);
	}

	char buf[128];
	size_t bytes = fbr_test_fs_read(fs, file, 0, buf, sizeof(buf));
	assert(bytes < sizeof(buf));
	buf[bytes] = '\0';
	if (append) {
		fbr_ASSERT(!strcmp(buf, "pre_rename append1 append2"), "found: '%s'", buf);
	} else {
		fbr_ASSERT(!strcmp(buf, " append2me"), "found: '%s'", buf);
	}

	fbr_dindex_release(fs, &root);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Cleanup fs");

	fbr_request_free(request);
	fbr_fs_release_all(fs, 1);

	fbr_test_cstore_debug(fs->cstore);
	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);

	if (append) {
		assert(fs->cstore->stats.wr_chunks == 3);
	} else {
		assert(fs->cstore->stats.wr_chunks == 2);
	}

	assert_zero(fs->stats.directories);
	assert_zero(fs->stats.directories_dindex);
	assert_zero(fs->stats.directory_refs);
	assert_zero(fs->stats.files);
	assert_zero(fs->stats.files_inodes);
	assert_zero(fs->stats.file_refs);

	fbr_fs_free(fs);

	if (append) {
		fbr_test_logs("rename_append_test done");
	} else {
		fbr_test_logs("rename_write_test done");
	}
}

void
fbr_cmd_rename_append_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_rename_test(ctx, 1);
}

void
fbr_cmd_rename_write_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_rename_test(ctx, 0);
}

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

#define _RENAME_FS_COUNT	1
#define _RENAME_THREADS		2
#define _RENAME_WRITE_MAX	500
#define _RENAME_WRITE_FILE	"write_data"
#define _RENAME_RENAME_FILE	"done"

static int _RENAME_DO_RANDOM_WRITE;
static size_t _RENAME_THREAD_COUNT;
static size_t _RENAME_WRITE_COUNTER;

struct _rename_data {
	struct {
		struct fbr_fs		*fs;
		pthread_t		thread;
		size_t			id;
		int			do_rename;
	} context;
	struct {
		size_t			count;
	} stats;
} _RENAME_DATA[_RENAME_FS_COUNT][_RENAME_THREADS];

void
_write_thread(struct _rename_data *data)
{
	struct fbr_fs *fs = data->context.fs;
	fbr_fs_ok(fs);

	struct fbr_request *request = _rename_request(fs);

	while (_RENAME_WRITE_COUNTER < _RENAME_WRITE_MAX) {
		struct fuse_file_info fi;
		fbr_zero(&fi);
		fi.flags = O_CREAT | O_WRONLY | O_APPEND;

		fbr_ops_create(request, FBR_INODE_ROOT, _RENAME_WRITE_FILE, S_IFREG, &fi);
		assert_zero(request->error);

		struct fbr_fio *fio = fbr_fh_fio(fi.fh);
		fbr_file_ok(fio->file);

		request = _rename_request(fs);

		fbr_ops_write(request, fio->file->inode, "test", 4, 0, &fi);
		assert_zero(request->error);

		request = _rename_request(fs);

		fbr_ops_release(request, fio->file->inode, &fi);
		assert_zero(request->error);

		break;
	}

	fbr_request_free(request);
}

static void *
_rename_thread(void *arg)
{
	struct _rename_data *data = arg;

	struct fbr_fs *fs = data->context.fs;
	fbr_fs_ok(fs);
	assert(data->context.thread == pthread_self());
	assert_zero(data->stats.count);
	assert_zero(_RENAME_WRITE_COUNTER);

	fbr_atomic_add(&_RENAME_THREAD_COUNT, 1);
	while (_RENAME_THREAD_COUNT != _RENAME_FS_COUNT * _RENAME_THREADS) {
		fbr_test_sleep_ms(1);
	}

	fbr_test_logs("*** rename thread %zu running (rename: %d)",
		data->context.id, data->context.do_rename);

	if (!data->context.do_rename) {
		_write_thread(data);
		return NULL;
	}

	struct fbr_request *request = _rename_request(fs);

	while (_RENAME_WRITE_COUNTER < _RENAME_WRITE_MAX) {
		struct fbr_directory *directory = fbr_directory_from_inode(fs, FBR_INODE_ROOT);
		fbr_directory_ok(directory);

		struct fbr_file *file = fbr_directory_find_file(directory, _RENAME_WRITE_FILE,
			strlen(_RENAME_WRITE_FILE));
		if (!file) {
			fbr_dindex_release(fs, &directory);
			fbr_test_sleep_ms(1);
			continue;
		}

		fbr_dindex_release(fs, &directory);

		request = _rename_request(fs);

		fbr_ops_rename(request, FBR_INODE_ROOT, _RENAME_WRITE_FILE, FBR_INODE_ROOT,
			_RENAME_RENAME_FILE, RENAME_NOREPLACE);
		assert_zero(request->error);

		break;
	}

	fbr_request_free(request);

	return NULL;
}

static void
_rename_cluster(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	fbr_test_conf_add("CSTORE_SERVER", "true");
	fbr_test_conf_add("CSTORE_SERVER_ADDRESS", "127.0.0.1");
	fbr_test_conf_add("CSTORE_SERVER_PORT", "0");
	fbr_test_conf_add("LOG_SIZE", "250000");

	fbr_test_random_seed();
	fbr_test_fuse_mock(ctx);
	fbr_test_request_pool_register(ctx);

	fbr_test_logs("*** Init fs_array[%d]", _RENAME_FS_COUNT);

	struct fbr_cstore *cstore_s3 = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(cstore_s3);
	assert(fbr_test_cstore_count(ctx) == 1);
	fbr_test_cstore_s3_mock(cstore_s3, NULL, "NA", "Key", "_secret");

	static_ASSERT(_RENAME_FS_COUNT > 0);
	struct fbr_fs *fs_array[_RENAME_FS_COUNT];
	for (size_t i = 0; i < fbr_array_len(fs_array); i++) {
		struct fbr_fs *fs = fbr_test_fs_mock(ctx);
		fbr_fs_ok(fs);
		fbr_test_cstore_bind_new(fs);
		fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
		fbr_test_cstore_backend_add(fs->cstore, cstore_s3, FBR_CSTORE_ROUTE_S3);
		fbr_directory_root_inode_init(fs);
		fs_array[i] = fs;
	}

	for (size_t i = 0; i < fbr_array_len(fs_array); i++) {
		for (size_t j = 0; j < fbr_array_len(fs_array); j++) {
			fbr_test_cstore_backend_add(fs_array[i]->cstore, fs_array[j]->cstore,
				FBR_CSTORE_ROUTE_CLUSTER);
		}
	}

	fbr_test_logs("*** Make root");

	fbr_test_fs_root_alloc(fs_array[0]);

	fbr_test_sleep_ms(20);

	fbr_test_logs("*** Spawn threads");

	static_ASSERT(_RENAME_THREADS >= 2);
	size_t renamers = 0;

	for (size_t i = 0; i < fbr_array_len(_RENAME_DATA); i++) {
		for (size_t j = 0; j < fbr_array_len(_RENAME_DATA[i]); j++) {
			struct _rename_data *data = &_RENAME_DATA[i][j];
			fbr_zero(data);

			data->context.fs = fs_array[i];
			data->context.id = (i * fbr_array_len(_RENAME_DATA)) + j;

			if (j == fbr_array_len(_RENAME_DATA[i]) - 1) {
				data->context.do_rename = 1;
				renamers++;
			}

			pt_assert(pthread_create(&data->context.thread, NULL, &_rename_thread,
				data));
		}
	}

	assert(renamers == _RENAME_FS_COUNT);

	fbr_test_logs("*** Join threads");

	for (size_t i = 0; i < fbr_array_len(_RENAME_DATA); i++) {
		for (size_t j = 0; j < fbr_array_len(_RENAME_DATA[i]); j++) {
			pt_assert(pthread_join(_RENAME_DATA[i][j].context.thread, NULL));
		}
	}

	assert(_RENAME_THREAD_COUNT == _RENAME_FS_COUNT * _RENAME_THREADS);

	fbr_test_sleep_ms(20);

	fbr_test_logs("*** Cleanup");

	for (size_t i = 0; i < fbr_array_len(fs_array); i++) {
		fbr_test_logs("FS_ARRAY[%zu]", i);
		_assert_fs(fs_array[i], 0);
		fbr_test_cstore_debug(fs_array[i]->cstore);
		fbr_fs_free(fs_array[i]);
	}

	fbr_test_logs("CSTORE_S3");
	fbr_test_cstore_debug(cstore_s3);

	fbr_test_logs("rename_cluster_test done");
}

void
fbr_cmd_rename_cluster_append_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	assert_zero(_RENAME_DO_RANDOM_WRITE);

	_rename_cluster(ctx);
}
