/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/store/test/fbr_dstore.h"

static const struct fbr_store_callbacks _INDEX_TEST_CALLBACKS = {
	.index_write_f = fbr_dstore_index_root_write,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

void
fbr_test_index_request_start(void)
{
	assert_zero(fbr_request_get());

	fuse_req_t fuse_req = (fuse_req_t)1;
	struct fbr_request *request = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(request);

	fbr_request_take_fuse(request);
	fbr_ZERO(&request->thread);

	request->not_fuse = 1;
}

void
fbr_test_index_request_finish(void)
{
	struct fbr_request *request = fbr_request_get();
	assert(request);

	fbr_request_free(request);
}

static struct fbr_file *
_index_add_file(struct fbr_fs *fs, struct fbr_directory *directory, int verbose)
{
	assert_dev(fs);
	assert_dev(directory);

	size_t id = directory->file_count;

	char filename_buf[100];
	int ret = snprintf(filename_buf, sizeof(filename_buf), "file_%zu", id);
	assert(ret > 0 && (size_t)ret < sizeof(filename_buf));

	if (verbose) {
		fbr_test_logs(" ** Adding file: %s", filename_buf);
	}

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, filename_buf);

	struct fbr_file *file = fbr_file_alloc(fs, directory, &filename);
	file->generation = 1;
	file->size = id * 4096;
	file->mode = S_IFREG | 0444;
	file->uid = 1000;
	file->gid = 1000;

	fbr_id_t chunk_id = fbr_id_gen();

	if (verbose) {
		chunk_id = 0;
	}

	for (size_t offset = 0, length = 0; offset < file->size; offset += length) {
		length = fbr_fs_chunk_size(offset);
		if (offset + length > file->size) {
			length = file->size - offset;
		}

		fbr_body_chunk_add(fs, file, chunk_id, offset, length);
	}

	file->state = FBR_FILE_OK;

	assert(directory->file_count == id + 1);

	return file;
}

static void
_index_validate_directory(struct fbr_directory *directory, int verbose)
{
	assert_dev(directory);
	assert(directory->state == FBR_DIRSTATE_OK);

	char filename[100];
	size_t chunk_count = 0;
	size_t byte_count = 0;

	for (size_t i = 0; i < directory->file_count; i++) {
		int ret = snprintf(filename, sizeof(filename), "file_%zu", i);
		assert(ret > 0 && (size_t)ret < sizeof(filename));

		size_t size = i * 4096;

		struct fbr_file *file = fbr_directory_find_file(directory, filename, ret);
		fbr_file_ok(file);
		fbr_test_ASSERT(file->size == size, "Bad file size %s %lu", filename, file->size);
		fbr_test_ASSERT(file->mode == (S_IFREG | 0444), "Bad file mode %s %u", filename,
			file->mode);
		fbr_test_ASSERT(file->uid == 1000, "Bad file uid %s %u", filename, file->uid);
		fbr_test_ASSERT(file->gid == 1000, "Bad file gid %s %u", filename, file->gid);
		fbr_test_ASSERT(file->generation == 1, "Bad file gen %s %lu", filename,
			file->generation);

		struct fbr_chunk *chunk = file->body.chunks;
		size_t chunk_size = 0;

		while (chunk) {
			fbr_chunk_ok(chunk);
			assert(chunk->offset == chunk_size);
			assert(chunk->length);

			if (verbose) {
				assert_zero(chunk->id);
			} else {
				assert(chunk->id);
			}

			chunk_size += chunk->length;
			chunk = chunk->next;

			chunk_count++;
		}

		assert(chunk_size == file->size);
		byte_count += file->size;

		const char *filepath = fbr_path_get_file(&file->path, NULL);
		assert_zero(strcmp(filepath, filename));

		if (verbose) {
			fbr_test_logs("  * Valid file: %s", filepath);
		}
	}

	fbr_test_logs("  * Valid files: %zu chunks: %zu bytes: %zu", directory->file_count,
		chunk_count, byte_count);
}

void
fbr_cmd_index_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_init(ctx);

	struct fbr_fs *fs = fbr_test_fuse_mock(ctx);
	fbr_fs_ok(fs);

	fbr_fs_set_store(fs, &_INDEX_TEST_CALLBACKS);

	fbr_test_logs("*** Allocating directory");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;
	_index_add_file(fs, directory, 1);
	_index_add_file(fs, directory, 1);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	fbr_test_index_request_start();

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, directory, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Making changes v1");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs, directory, directory->previous);
	directory->generation++;
	_index_add_file(fs, directory, 1);
	_index_add_file(fs, directory, 1);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	fbr_test_index_request_start();

	fs->config.gzip_index = 0;

	fbr_index_data_init(NULL, &index_data, directory, directory->previous, NULL, NULL,
		FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	_index_validate_directory(directory, 1);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fs->config.gzip_index = 1;

	fbr_test_logs("*** Releasing directory");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_test_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	_index_validate_directory(directory, 1);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Loading index again");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_test_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Making changes v2");

	struct fbr_directory *old_directory = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(old_directory);

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->previous == old_directory)
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs, directory, directory->previous);
	directory->generation++;
	struct fbr_file *file = _index_add_file(fs, directory, 1);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	fbr_test_index_request_start();

	fbr_index_data_init(fs, &index_data, directory, directory->previous, file, NULL,
		FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	_index_validate_directory(directory, 1);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Making changes v3");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->previous != old_directory)
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs, directory, directory->previous);
	directory->generation++;
	_index_add_file(fs, directory, 1);

	fbr_test_logs("*** Storing index (gen %lu) FAIL", directory->generation);

	fbr_test_index_request_start();

	fbr_index_data_init(NULL, &index_data, directory, old_directory, NULL, NULL,
		FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	fbr_test_ASSERT(ret, "fbr_index_write() did NOT fail");
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_index_data_free(&index_data);

	fbr_test_index_request_finish();

	fbr_test_logs("*** Storing index (gen %lu) FAIL v2", directory->generation);

	fbr_test_index_request_start();

	fbr_index_data_init(NULL, &index_data, directory, NULL, NULL, NULL, FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	fbr_test_ASSERT(ret, "fbr_index_write() did NOT fail");
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_index_data_free(&index_data);

	fbr_test_index_request_finish();

	fbr_test_logs("*** Storing index (gen %lu) RETRY", directory->generation);

	fbr_test_index_request_start();

	fbr_directory_ok(directory->previous);
	fbr_index_data_init(NULL, &index_data, directory, directory->previous, NULL, NULL,
		FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	_index_validate_directory(directory, 1);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Releasing directory v2");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index v2 (duplicate error)");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous); // We are olding old_directory...
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_test_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);
	fbr_dindex_release(fs, &old_directory);

	fbr_test_logs("*** Releasing directory v3");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index v3");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_test_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	_index_validate_directory(directory, 1);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Cleanup");
	fbr_fs_release_all(fs, 1);

	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);
	fbr_dstore_debug(1);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");
	fbr_test_ERROR(fs->stats.buffers, "non zero");

	fbr_request_pool_shutdown(fs);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "index_test done");
}

void
fbr_cmd_index_large_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_init(ctx);

	struct fbr_fs *fs = fbr_test_fuse_mock(ctx);
	fbr_fs_ok(fs);

	fbr_fs_set_store(fs, &_INDEX_TEST_CALLBACKS);

	fbr_test_logs("*** Allocating directory");

	size_t MAX_FILES = 10000;

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;
	for (size_t i = 0; i < MAX_FILES; i++) {
		_index_add_file(fs, directory, 0);
	}

	fbr_test_logs("*** Allocated %zu files", directory->file_count);
	assert(directory->file_count == MAX_FILES);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	fbr_test_index_request_start();

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, directory, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Releasing directory");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_test_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	_index_validate_directory(directory, 0);

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Cleanup");
	fbr_fs_release_all(fs, 1);

	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);
	fbr_dstore_debug(0);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_request_pool_shutdown(fs);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "index_large_test done");
}

void
fbr_cmd_index_2fs_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_init(ctx);

	struct fbr_fs *fs_1 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_1);
	fbr_fs_set_store(fs_1, &_INDEX_TEST_CALLBACKS);

	struct fbr_fs *fs_2 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_2);
	fbr_fs_set_store(fs_2, &_INDEX_TEST_CALLBACKS);

	fbr_test_logs("*** Allocating dir_fs1");

	struct fbr_directory *dir_fs1 = fbr_directory_root_alloc(fs_1);
	fbr_directory_ok(dir_fs1);
	assert_zero(dir_fs1->previous);
	assert(dir_fs1->state == FBR_DIRSTATE_LOADING);
	dir_fs1->generation = 1;
	_index_add_file(fs_1, dir_fs1, 1);
	_index_add_file(fs_1, dir_fs1, 1);
	_index_add_file(fs_1, dir_fs1, 1);

	fbr_test_logs("*** Storing dir_fs1 (gen %lu)", dir_fs1->generation);

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, dir_fs1, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs_1, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs_1, dir_fs1, FBR_DIRSTATE_OK);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Loading dir_fs2");

	struct fbr_directory *dir_fs2 = fbr_directory_root_alloc(fs_2);
	fbr_directory_ok(dir_fs2);
	assert_zero(dir_fs2->previous);
	assert(dir_fs2->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_2, dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 1);
	_index_validate_directory(dir_fs2, 1);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Making changes dir_fs2");

	dir_fs2 = fbr_directory_root_alloc(fs_2);
	fbr_directory_ok(dir_fs2);
	fbr_directory_ok(dir_fs2->previous);
	assert(dir_fs2->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs_2, dir_fs2, dir_fs2->previous);
	dir_fs2->generation++;
	_index_add_file(fs_2, dir_fs2, 1);
	_index_add_file(fs_2, dir_fs2, 1);
	_index_add_file(fs_2, dir_fs2, 1);

	fbr_test_logs("*** Storing dir_fs2 (gen %lu)", dir_fs2->generation);

	fbr_index_data_init(NULL, &index_data, dir_fs2, dir_fs2->previous, NULL, NULL,
		FBR_FLUSH_NONE);
	ret = fbr_index_write(fs_2, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs_2, dir_fs2, FBR_DIRSTATE_OK);
	_index_validate_directory(dir_fs2, 1);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Loading dir_fs1 (previously gen 1)");

	dir_fs1 = fbr_directory_root_alloc(fs_1);
	fbr_directory_ok(dir_fs1);
	fbr_directory_ok(dir_fs1->previous);
	assert(dir_fs1->previous->generation == 1);
	assert(dir_fs1->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_1, dir_fs1);
	assert(dir_fs1->state == FBR_DIRSTATE_OK);
	assert(dir_fs1->generation == 2);
	_index_validate_directory(dir_fs1, 1);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Cleanup fs_1");

	fbr_fs_release_all(fs_1, 1);

	fbr_test_fs_stats(fs_1);
	fbr_test_fs_inodes_debug(fs_1);
	fbr_test_fs_dindex_debug(fs_1);

	fbr_test_ERROR(fs_1->stats.directories, "non zero");
	fbr_test_ERROR(fs_1->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_1->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_1->stats.files, "non zero");
	fbr_test_ERROR(fs_1->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_1->stats.file_refs, "non zero");

	fbr_fs_free(fs_1);

	fbr_test_logs("*** Cleanup fs_2");

	fbr_fs_release_all(fs_2, 1);

	fbr_test_fs_stats(fs_2);
	fbr_test_fs_inodes_debug(fs_2);
	fbr_test_fs_dindex_debug(fs_2);
	fbr_dstore_debug(0);

	fbr_test_ERROR(fs_2->stats.directories, "non zero");
	fbr_test_ERROR(fs_2->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_2->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_2->stats.files, "non zero");
	fbr_test_ERROR(fs_2->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_2->stats.file_refs, "non zero");

	fbr_fs_free(fs_2);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "index_2fs_test done");
}

#define _THREADS_MAX 4
static size_t _THREAD_COUNT;

void *
_index_thread(void *arg)
{
	assert_zero(arg);

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fs->logger = fbr_test_fs_logger_null;
	fbr_fs_set_store(fs, &_INDEX_TEST_CALLBACKS);

	size_t thread_id = fbr_atomic_add(&_THREAD_COUNT, 1);
	fbr_test_logs("*** thread %zu running", thread_id);
	while (_THREAD_COUNT < _THREADS_MAX) {
		fbr_sleep_ms(0.1);
	}
	assert(_THREAD_COUNT == _THREADS_MAX);

	unsigned long generation = 0;

	// Modify write/read loop

	while (generation < 10) {
		struct fbr_directory *directory = fbr_directory_root_alloc(fs);
		fbr_directory_ok(directory);
		assert(directory->state == FBR_DIRSTATE_LOADING);

		if (!directory->previous) {
			directory->generation = 1;
		} else {
			fbr_directory_ok(directory->previous);
			fbr_directory_copy(fs, directory, directory->previous);
			directory->generation++;
		}

		struct fbr_file *file = _index_add_file(fs, directory, 0);
		assert(directory->generation == directory->file_count);

		struct fbr_index_data index_data;
		fbr_index_data_init(fs, &index_data, directory, directory->previous, file, NULL,
			FBR_FLUSH_NONE);
		int ret = fbr_index_write(fs, &index_data);
		fbr_index_data_free(&index_data);

		fbr_test_logs("*** Storing index thread: %zu generation: %lu result: %d",
			thread_id, directory->generation, ret);

		// Read root if you didnt allocate it
		if (ret) {
			fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);

			do {
				fbr_dindex_release(fs, &directory);

				directory = fbr_directory_root_alloc(fs);
				fbr_directory_ok(directory);
				assert(directory->state == FBR_DIRSTATE_LOADING);

				fbr_index_read(fs, directory);
			} while (directory->state == FBR_DIRSTATE_ERROR);

			assert(directory->state == FBR_DIRSTATE_OK);

			fbr_test_logs("*** Reading index thread: %zu generation: %lu",
				thread_id, directory->generation);
		} else {
			fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
			fbr_sleep_ms(5);
		}

		_index_validate_directory(directory, 0);
		assert(directory->generation == directory->file_count);

		generation = directory->generation;

		fbr_dindex_release(fs, &directory);
	}

	fbr_fs_release_all(fs, 1);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_fs_free(fs);

	return NULL;
}

void
fbr_cmd_index_2fs_thread_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_init(ctx);

	pthread_t threads[_THREADS_MAX];
	_THREAD_COUNT = 0;

	for (size_t i = 0; i < _THREADS_MAX; i++) {
		pt_assert(pthread_create(&threads[i], NULL, _index_thread, NULL));
	}

	fbr_test_logs("*** threads created: %d", _THREADS_MAX);

	for (size_t i = 0; i < _THREADS_MAX; i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}

	fbr_test_logs("*** all threads joined");

	fbr_dstore_debug(0);

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fs->logger = fbr_test_fs_logger_null;
	fbr_fs_set_store(fs, &_INDEX_TEST_CALLBACKS);

	fbr_test_logs("*** Final read and validation");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);

	_index_validate_directory(directory, 0);
	assert(directory->generation == directory->file_count);

	fbr_dindex_release(fs, &directory);
	fbr_fs_release_all(fs, 1);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "index_2fs_test done");
}
