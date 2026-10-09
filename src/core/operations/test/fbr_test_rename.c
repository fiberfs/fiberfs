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
#include <stdlib.h>

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

extern int _FBR_WRITE_DEBUG;

void fbr_inode_set_start(struct fbr_fs *fs, fbr_inode_t start);

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

static unsigned long
_pow(unsigned long base, unsigned long exp)
{
	assert(exp < 20);

	unsigned long result = 1;

	while (exp) {
		result *= base;
		exp--;
	}

	return result;
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

#define _RENAME_FS_COUNT	3
#define _RENAME_THREADS		3
#define _RENAME_WRITE_FILE_MAX	5
#define _RENAME_WRITE_MAX	50
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
		size_t			fs_id;
		int			do_rename;
	} context;
	struct {
		size_t			write_loops;
		size_t			rename_loops;
		size_t			rename_count;
		size_t			rename_success;
		size_t			rename_source_notfound;
		size_t			rename_dest_exists;
		size_t			rename_error;
	} stats;
} _RENAME_DATA[_RENAME_FS_COUNT][_RENAME_THREADS];

static struct fbr_request *
_rename_request_data(struct _rename_data *data)
{
	assert(data);

	struct fbr_request *request = _rename_request(data->context.fs);
	assert(request);

	request->id = request->id * _pow(10, data->context.fs_id);
	request->rlog->request_id = request->id;

	return request;
}

void
_write_thread(struct _rename_data *data)
{
	struct fbr_fs *fs = data->context.fs;
	fbr_fs_ok(fs);

	struct fbr_request *request = NULL;

	while (_RENAME_WRITE_COUNTER < _RENAME_WRITE_MAX) {
		request = _rename_request_data(data);

		struct fuse_file_info fi;
		fbr_zero(&fi);
		fi.flags = O_CREAT | O_WRONLY | O_APPEND;

		fbr_ops_create(request, FBR_INODE_ROOT, _RENAME_WRITE_FILE, S_IFREG, &fi);
		assert_zero(request->error);

		struct fbr_fio *fio = fbr_fh_fio(fi.fh);
		fbr_file_ok(fio->file);

		static_ASSERT(_RENAME_WRITE_FILE_MAX > 1);
		static_ASSERT(_RENAME_WRITE_FILE_MAX < _RENAME_WRITE_MAX);
		size_t max = fbr_test_gen_random(1, _RENAME_WRITE_FILE_MAX);
		for (size_t i = 0; i < max; i++) {
			request = _rename_request_data(data);

			size_t count = fbr_atomic_add(&_RENAME_WRITE_COUNTER, 1);

			char buf[32];
			size_t buf_len = fbr_bprintf(buf, "%zu ", count);

			fbr_ops_write(request, fio->file->inode, buf, buf_len, 0, &fi);
			assert_zero(request->error);
		}

		request = _rename_request_data(data);

		fbr_ops_release(request, fio->file->inode, &fi);
		assert_zero(request->error);

		data->stats.write_loops++;

		fbr_test_sleep_ms(fbr_test_gen_random(100, 200));
	}

	if (request) {
		fbr_request_free(request);
	}
}

static void *
_rename_thread(void *arg)
{
	struct _rename_data *data = arg;

	struct fbr_fs *fs = data->context.fs;
	fbr_fs_ok(fs);
	assert(data->context.thread == pthread_self());
	assert_zero(data->stats.rename_count);
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

	struct fbr_request *request = NULL;

	while (_RENAME_WRITE_COUNTER < _RENAME_WRITE_MAX) {
		request = _rename_request_data(data);

		char rename_dest[32];
		fbr_bprintf(rename_dest, "%s_%zu", _RENAME_RENAME_FILE,
			data->stats.rename_count);

		fbr_ops_rename(request, FBR_INODE_ROOT, _RENAME_WRITE_FILE, FBR_INODE_ROOT,
			rename_dest, RENAME_NOREPLACE);

		switch(request->error) {
			case 0:
				fbr_stat_add(&data->stats.rename_success);
				break;
			case ENOENT:
				fbr_stat_add(&data->stats.rename_source_notfound);
				break;
			case EEXIST:
				fbr_atomic_add(&data->stats.rename_count, 1);
				fbr_stat_add(&data->stats.rename_dest_exists);
				break;
			default:
				fbr_stat_add(&data->stats.rename_error);
				break;
		}

		if (request->error) {
			fbr_test_sleep_ms(fbr_test_gen_random(10, 20));
		} else {
			fbr_test_sleep_ms(fbr_test_gen_random(100, 200));
		}

		request->error = 0;
		data->stats.rename_loops++;
	}

	if (request) {
		fbr_request_free(request);
	}

	return NULL;
}

static void
_rename_validate_counts(struct fbr_fs *fs, struct fbr_file *file, int *write_validate,
    int *write_count)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(write_validate);
	assert(write_count);

	char buffer[1024];
	size_t buffer_len = fbr_test_fs_read(fs, file, 0, buffer, sizeof(buffer));
	assert(buffer_len);
	assert(buffer_len < sizeof(buffer));
	buffer[buffer_len] = '\0';

	size_t values = 0;
	char *check_pos = buffer;
	while (*check_pos) {
		char *end = NULL;
		long value = strtol(check_pos, &end, 10);
		assert(end && *end == ' ');
		assert(value > 0 && (size_t)value <= _RENAME_WRITE_COUNTER);

		write_validate[value - 1]++;

		check_pos = end + 1;
		values++;
	}

	*write_count = values;
}

static void
_rename_cluster(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	fbr_test_conf_add("CSTORE_SERVER", "true");
	fbr_test_conf_add("CSTORE_SERVER_ADDRESS", "127.0.0.1");
	fbr_test_conf_add("CSTORE_SERVER_PORT", "0");
	fbr_test_conf_add("LOG_SIZE", "3000000");

	_FBR_WRITE_DEBUG = 1;

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

		long offset = _pow(10, i);
		fbr_inode_set_start(fs, FBR_INODES_START * offset);

		fbr_test_cstore_bind_new(fs);
		fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
		fbr_test_cstore_backend_add(fs->cstore, cstore_s3, FBR_CSTORE_ROUTE_S3);
		fbr_directory_root_inode_init(fs);
		fs_array[i] = fs;
	}

	// TODO skipping cluster for now
	/*
	for (size_t i = 0; i < fbr_array_len(fs_array); i++) {
		for (size_t j = 0; j < fbr_array_len(fs_array); j++) {
			fbr_test_cstore_backend_add(fs_array[i]->cstore, fs_array[j]->cstore,
				FBR_CSTORE_ROUTE_CLUSTER);
		}
	}
	*/

	fbr_test_logs("*** Make root");

	fbr_test_fs_root_alloc(fs_array[0]);

	for (size_t i = 1; i < fbr_array_len(fs_array); i++) {
		struct fbr_directory *root = fbr_directory_from_inode(fs_array[i], FBR_INODE_ROOT);
		fbr_directory_ok(root);
		assert(root->state == FBR_DIRSTATE_OK);
		fbr_dindex_release(fs_array[i], &root);
	}

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
			data->context.fs_id = i;

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

	fbr_test_sleep_ms(100);

	fbr_test_logs("*** Validate");

	int *write_validate = calloc(_RENAME_WRITE_COUNTER, sizeof(*write_validate));
	assert(write_validate);

	int *write_counts = realloc(NULL, sizeof(*write_counts));
	assert(write_counts);

	struct fbr_fs *fs = fs_array[0];
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 1);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	struct fbr_file *file = fbr_directory_find_file(root, _RENAME_WRITE_FILE,
		strlen(_RENAME_WRITE_FILE));
	if (file) {
		fbr_file_ok(file);
		assert (file->state == FBR_FILE_OK);

		fbr_test_logs("VALIDATE %s exists", _RENAME_WRITE_FILE);

		_rename_validate_counts(fs, file, write_validate, &write_counts[0]);
	}

	size_t rename_count = 0;
	while (1) {
		char rename_dest[32];
		size_t len = fbr_bprintf(rename_dest, "%s_%zu", _RENAME_RENAME_FILE,
			rename_count);

		file = fbr_directory_find_file(root, rename_dest, len);
		if (!file) {
			break;
		}

		fbr_file_ok(file);
		assert(file->state == FBR_FILE_OK);

		fbr_test_logs("%s exists", rename_dest);

		write_counts = realloc(write_counts, sizeof(*write_counts) * (rename_count + 2));

		_rename_validate_counts(fs, file, write_validate, &write_counts[rename_count + 1]);

		rename_count++;
	}

	fbr_test_sleep_ms(20);

	for (size_t i = 0; i <= rename_count; i++) {
		if (!i) {
			fbr_test_logs("File %s: %d writes", _RENAME_WRITE_FILE, write_counts[i]);
		} else {
			fbr_test_logs("File %s_%zu: %d writes", _RENAME_RENAME_FILE, i - 1,
				write_counts[i]);
		}
	}

	int errors = 0;
	for (size_t i = 0; i < _RENAME_WRITE_COUNTER; i++) {
		fbr_test_logs("  count: %zu value: %d", i + 1, write_validate[i]);

		if (write_validate[i] != 1) {
			errors++;
		}
	}

	fbr_test_logs("_RENAME_WRITE_COUNTER=%zu", _RENAME_WRITE_COUNTER);

	for (size_t i = 0; i < fbr_array_len(_RENAME_DATA); i++) {
		for (size_t j = 0; j < fbr_array_len(_RENAME_DATA[i]); j++) {
			struct _rename_data *data = &_RENAME_DATA[i][j];
			fbr_fs_ok(data->context.fs);

			fbr_test_logs("_RENAME_DATA[%zu][%zu] (rename: %d)", i, j,
				data->context.do_rename);

			if (data->context.do_rename) {
				fbr_test_logs("DATA.stats.rename_loops=%zu",
					data->stats.rename_loops);
				fbr_test_logs("DATA.stats.rename_count=%zu",
					data->stats.rename_count);
				fbr_test_logs("DATA.stats.rename_success=%zu",
					data->stats.rename_success);
				fbr_test_logs("DATA.stats.rename_source_notfound=%zu",
					data->stats.rename_source_notfound);
				fbr_test_logs("DATA.stats.rename_dest_exists=%zu",
					data->stats.rename_dest_exists);
				fbr_test_logs("DATA.stats.rename_error=%zu",
					data->stats.rename_error);
			} else {
				fbr_test_logs("DATA.stats.write_loops=%zu",
					data->stats.write_loops);
			}
		}
	}

	fbr_ASSERT(!errors, "error(s) found: %d", errors);

	fbr_test_logs("Renamed writes passed validation!");

	free(write_validate);
	free(write_counts);
	fbr_dindex_release(fs, &root);
	fs = NULL;

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Cleanup");

	for (size_t i = 0; i < fbr_array_len(fs_array); i++) {
		fbr_test_logs("FS_ARRAY[%zu]", i);
		_assert_fs(fs_array[i], 0);
		//fbr_test_cstore_debug(fs_array[i]->cstore);
		fbr_test_cstore_wait(fs_array[i]->cstore);
		fbr_fs_free(fs_array[i]);
	}

	fbr_test_logs("CSTORE_S3");
	//fbr_test_cstore_debug(cstore_s3);
	fbr_test_cstore_wait(cstore_s3);

	assert(cstore_s3->stats.wr_chunks == _RENAME_WRITE_COUNTER);

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
