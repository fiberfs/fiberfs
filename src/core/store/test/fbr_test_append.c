/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/store/test/fbr_dstore.h"

static const struct fbr_store_callbacks _APPEND_TEST_CALLBACKS = {
	.chunk_read_f = fbr_dstore_chunk_read,
	.chunk_delete_f = fbr_dstore_chunk_delete,
	.wbuffer_write_f = fbr_dstore_wbuffer_write,
	.directory_flush_f = fbr_directory_flush,
	.index_write_f = fbr_dstore_index_root_write,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

void
fbr_cmd_append_2fs_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_init(ctx);

	struct fbr_fs *fs_1 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_1);
	fbr_fs_set_store(fs_1, &_APPEND_TEST_CALLBACKS);

	struct fbr_fs *fs_2 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_2);
	fbr_fs_set_store(fs_2, &_APPEND_TEST_CALLBACKS);

	fbr_test_logs("*** Allocating dir_fs1");

	struct fbr_directory *dir_fs1 = fbr_directory_root_alloc(fs_1);
	fbr_directory_ok(dir_fs1);
	assert_zero(dir_fs1->previous);
	assert(dir_fs1->state == FBR_DIRSTATE_LOADING);
	dir_fs1->generation = 1;

	fbr_test_logs("*** Storing dir_fs1 (gen %lu)", dir_fs1->generation);

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, dir_fs1, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs_1, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write(fs_1) failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs_1, dir_fs1, FBR_DIRSTATE_OK);
	assert_zero(dir_fs1->file_count);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Loading dir_fs2");

	struct fbr_directory *dir_fs2 = fbr_directory_root_alloc(fs_2);
	fbr_directory_ok(dir_fs2);
	assert_zero(dir_fs2->previous);
	assert(dir_fs2->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_2, dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 1);
	assert_zero(dir_fs2->file_count);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Write file.append on dir_fs1 (111)");

	dir_fs1 = fbr_dindex_take(fs_1, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs1);
	assert(dir_fs1->state == FBR_DIRSTATE_OK);
	assert_zero(dir_fs1->previous);
	assert(dir_fs1->generation == 1);
	assert_zero(dir_fs1->file_count);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, "file.append");
	struct fbr_file *file = fbr_file_alloc_new(fs_1, dir_fs1, &filename);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_INIT);
	assert_zero(file->size);

	struct fbr_fio *fio = fbr_fio_alloc(fs_1, file, 0);
	fio->append = 1;
	fbr_wbuffer_write(fs_1, fio, 0, "111", 3);
	ret = fbr_wbuffer_flush_fio(fs_1, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_1) failed");
	fbr_fio_release(fs_1, fio);

	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->size == 3);
	assert(file->generation == 1);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Write file.append on dir_fs2 (2222)");

	dir_fs2 = fbr_dindex_take(fs_2, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert_zero(dir_fs2->previous);
	assert(dir_fs2->generation == 1);
	assert_zero(dir_fs2->file_count);

	file = fbr_file_alloc_new(fs_2, dir_fs2, &filename);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_INIT);
	assert_zero(file->size);

	fio = fbr_fio_alloc(fs_2, file, 0);
	fio->append = 1;
	fbr_wbuffer_write(fs_2, fio, 0, "2222", 4);
	ret = fbr_wbuffer_flush_fio(fs_2, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_2) failed");
	fbr_fio_release(fs_2, fio);

	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->size == 7);
	assert(file->generation == 2);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Write file.append on dir_fs1 (333)");

	dir_fs1 = fbr_dindex_take(fs_1, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs1);
	assert(dir_fs1->state == FBR_DIRSTATE_OK);
	assert_zero(dir_fs1->previous);
	assert(dir_fs1->generation == 2);
	assert(dir_fs1->file_count == 1);

	file = fbr_directory_find_file(dir_fs1, filename.name, filename.len);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->size == 3);

	fio = fbr_fio_alloc(fs_1, file, 0);
	fio->append = 1;
	fbr_wbuffer_write(fs_1, fio, 0, "333", 3);
	ret = fbr_wbuffer_flush_fio(fs_1, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_1) failed");
	fbr_fio_release(fs_1, fio);

	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->size == 10);
	assert(file->generation == 3);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Loading dir_fs2 and validate");

	dir_fs2 = fbr_directory_root_alloc(fs_2);
	fbr_directory_ok(dir_fs2);
	assert(dir_fs2->previous);
	assert(dir_fs2->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_2, dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 4);
	assert(dir_fs2->file_count == 1);

	file = fbr_directory_find_file(dir_fs2, filename.name, filename.len);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->size == 10);
	assert(file->generation == 3);

	char buffer[100];
	size_t bytes = fbr_test_fs_read(fs_2, file, 0, buffer, sizeof(buffer));
	fbr_test_ASSERT(bytes == 10, "Found %zu", bytes);
	fbr_test_ASSERT(!memcmp(buffer, "1112222333", bytes), "Body mismatch '%.*s'", 10, buffer);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Cleanup fs_1");

	fbr_fs_release_all(fs_1, 1);

	fbr_test_fs_stats(fs_1);
	fbr_test_fs_inodes_debug(fs_1);
	fbr_test_fs_dindex_debug(fs_1);

	assert_zero(fs_1->stats.directories);
	assert_zero(fs_1->stats.directories_dindex);
	assert_zero(fs_1->stats.directory_refs);
	assert_zero(fs_1->stats.files);
	assert_zero(fs_1->stats.files_inodes);
	assert_zero(fs_1->stats.file_refs);
	assert(fs_1->stats.appends == 2);
	assert(fs_1->stats.merges == 1);

	fbr_fs_free(fs_1);

	fbr_test_logs("*** Cleanup fs_2");

	fbr_fs_release_all(fs_2, 1);

	fbr_test_fs_stats(fs_2);
	fbr_test_fs_inodes_debug(fs_2);
	fbr_test_fs_dindex_debug(fs_2);
	fbr_dstore_debug(0);

	assert_zero(fs_2->stats.directories);
	assert_zero(fs_2->stats.directories_dindex);
	assert_zero(fs_2->stats.directory_refs);
	assert_zero(fs_2->stats.files);
	assert_zero(fs_2->stats.files_inodes);
	assert_zero(fs_2->stats.file_refs);
	assert(fs_2->stats.appends == 1);
	assert(fs_2->stats.merges == 1);

	fbr_fs_free(fs_2);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "append_2fs_test done");
}

#define _APPEND_THREADS		8
#define _APPEND_COUNTER_MAX	32
size_t _APPEND_THREAD_COUNT;
size_t _APPEND_COUNTER;

static void *
_append_thread(void *arg)
{
	assert_zero(arg);

	assert_zero(_APPEND_COUNTER);
	size_t id = fbr_atomic_add(&_APPEND_THREAD_COUNT, 1);

	fbr_test_logs(" ** Thread %zu running", id);

	while (_APPEND_THREAD_COUNT < _APPEND_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_APPEND_THREAD_COUNT == _APPEND_THREADS);

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, &_APPEND_TEST_CALLBACKS);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, "file.append-thread");

	size_t count = fbr_atomic_add(&_APPEND_COUNTER, 1);

	while (count <= _APPEND_COUNTER_MAX) {
		struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
		if (!root) {
			root = fbr_directory_root_alloc(fs);
			fbr_directory_ok(root);
			assert(root->state == FBR_DIRSTATE_LOADING);
			fbr_index_read(fs, root);
		}
		fbr_directory_ok(root);
		assert(root->state == FBR_DIRSTATE_OK);

		struct fbr_file *file = fbr_directory_find_file(root, filename.name, filename.len);
		if (file) {
			fbr_file_ok(file);
			assert(file->state == FBR_FILE_OK);
		} else {
			file = fbr_file_alloc_new(fs, root, &filename);
			fbr_file_ok(file);
			assert(file->state == FBR_FILE_INIT);
		}

		char buffer[32];
		size_t buffer_len = snprintf(buffer, sizeof(buffer), "%zu ", count);
		assert(buffer_len < sizeof(buffer));

		struct fbr_fio *fio = fbr_fio_alloc(fs, file, 0);
		fio->append = 1;
		fbr_wbuffer_write(fs, fio, 0, buffer, buffer_len);
		int ret = fbr_wbuffer_flush_fio(fs, fio);
		fbr_test_ERROR(ret, "thread %zu fbr_wbuffer_flush_fio(fs) failed", id);
		fbr_fio_release(fs, fio);

		fbr_dindex_release(fs, &root);

		count = fbr_atomic_add(&_APPEND_COUNTER, 1);
	}

	fbr_fs_release_all(fs, 1);
	fbr_fs_free(fs);

	fbr_test_logs(" ** Thread %zu done", id);

	return NULL;
}

void
fbr_cmd_append_thread_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_init(ctx);

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, &_APPEND_TEST_CALLBACKS);

	fbr_test_logs("*** Allocating root");

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);
	root->generation = 1;

	fbr_test_logs("*** Storing root (gen %lu)", root->generation);

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, root, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write(fs) failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	fbr_dindex_release(fs, &root);

	fbr_test_logs("*** Starting threads...");

	assert_zero(_APPEND_THREAD_COUNT);
	assert_zero(_APPEND_COUNTER);
	pthread_t threads[_APPEND_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _append_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_APPEND_THREAD_COUNT == _APPEND_THREADS);

	fbr_test_logs("*** Threads done");

	fbr_test_logs("*** Validation");

	root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);
	fbr_index_read(fs, root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert(root->generation == _APPEND_COUNTER_MAX + 1);
	assert(root->file_count == 1);

	fbr_test_logs("*** root generation: %lu", root->generation);

	struct fbr_file *file = fbr_directory_find_file(root, "file.append-thread", 18);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	assert(file->generation == _APPEND_COUNTER_MAX);

	fbr_test_logs("*** root->generation: %lu file->generation: %lu", root->generation,
		file->generation);

	char buffer[4096];
	fbr_test_ASSERT(sizeof(buffer) > file->size, "file->size too big: %lu", file->size);
	size_t bytes = fbr_test_fs_read(fs, file, 0, buffer, sizeof(buffer));
	assert(bytes == file->size);
	buffer[file->size] = '\0';

	int checks[_APPEND_COUNTER_MAX + 1];
	memset(checks, 0, sizeof(checks));
	char *check_pos = buffer;
	while (*check_pos) {
		char *end = NULL;
		long value = strtol(check_pos, &end, 10);
		assert(end && *end == ' ');
		assert(value > 0 && value <= _APPEND_COUNTER_MAX);
		check_pos = end + 1;
		checks[value] = 1;
	}

	for (size_t i = 1; i <= _APPEND_COUNTER_MAX; i++) {
		fbr_test_ASSERT(checks[i], "%zu missing from check", i);
	}

	assert(fbr_dstore_stat_chunks() == _APPEND_COUNTER_MAX);

	fbr_test_logs("*** All %d checks PASSED", _APPEND_COUNTER_MAX);

	fbr_dindex_release(fs, &root);

	fbr_test_logs("*** Cleanup fs");

	fbr_fs_release_all(fs, 1);
	fbr_fs_free(fs);
	fbr_dstore_debug(0);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "append_thread_test done");
}
