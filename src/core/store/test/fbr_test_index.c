/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/store/test/fbr_dstore.h"

static unsigned int _INDEX_FILE_COUNTER;
static unsigned long _INDEX_GENERATION;

static const struct fbr_store_callbacks _INDEX_TEST_CALLBACKS = {
	.index_write_f = fbr_dstore_index_root_write,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

static void
_index_request_start(void)
{
	assert_zero(fbr_request_get());

	fuse_req_t fuse_req = (fuse_req_t)1;
	struct fbr_request *request = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(request);

	fbr_request_take_fuse(request);
	fbr_ZERO(&request->thread);

	request->not_fuse = 1;
}

static void
_index_request_finish(void)
{
	struct fbr_request *request = fbr_request_get();
	assert(request);

	fbr_request_free(request);
}

static void
_index_add_file(struct fbr_fs *fs, struct fbr_directory *directory)
{
	assert_dev(fs);
	assert_dev(directory);

	char filename_buf[100];
	int ret = snprintf(filename_buf, sizeof(filename_buf), "file_%u", _INDEX_FILE_COUNTER);
	assert(ret > 0 && (size_t)ret < sizeof(filename_buf));

	fbr_test_logs(" ** Adding file: %s", filename_buf);

	_INDEX_FILE_COUNTER++;

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, filename_buf);

	struct fbr_file *file = fbr_file_alloc(fs, directory, &filename);
	file->generation = 1;
	file->size = _INDEX_FILE_COUNTER * 100;
	file->mode = S_IFREG | 0444;
	file->uid = 1000;
	file->gid = 1000;
	fbr_body_chunk_add(fs, file, 0, 0, file->size);
	file->state = FBR_FILE_OK;
}

static void
_index_validate_directory(struct fbr_directory *directory)
{
	assert_dev(directory);

	fbr_test_ASSERT(directory->generation == _INDEX_GENERATION,
		"Generation mismatch, found %lu, expected %lu", directory->generation,
		_INDEX_GENERATION);

	fbr_test_logs("  * Valid generation: %lu", directory->generation);

	char filename[100];

	for (size_t i = 0; i < _INDEX_FILE_COUNTER; i++) {
		int ret = snprintf(filename, sizeof(filename), "file_%zu", i);
		assert(ret > 0 && (size_t)ret < sizeof(filename));

		size_t size = (i + 1) * 100;

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
		fbr_chunk_ok(chunk);
		assert_zero(chunk->next);
		assert_zero(chunk->id);
		assert_zero(chunk->offset);
		fbr_test_ASSERT(chunk->length == size, "Bad chunk size %lu", chunk->length);

		const char *filename = fbr_path_get_file(&file->path, NULL);
		fbr_test_logs("  * Valid file: %s", filename);
	}
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
	_INDEX_GENERATION++;
	_index_add_file(fs, directory);
	_index_add_file(fs, directory);
	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	_index_request_start();

	int ret = fbr_index_write(fs, directory, NULL);
	fbr_test_ERROR(ret, "fbr_index_write() failed");

	_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Making changes v1");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs, directory->previous, directory);
	directory->generation++;
	_INDEX_GENERATION++;
	_index_add_file(fs, directory);
	_index_add_file(fs, directory);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	_index_request_start();

	ret = fbr_index_write(fs, directory, directory->previous);
	fbr_test_ERROR(ret, "fbr_index_write() failed");

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	_index_validate_directory(directory);

	_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Releasing directory");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	_index_validate_directory(directory);

	_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Loading index again");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);

	_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Making changes v2");

	struct fbr_directory *old_directory = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(old_directory);

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->previous == old_directory)
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs, directory->previous, directory);
	directory->generation++;
	_INDEX_GENERATION++;
	_index_add_file(fs, directory);

	fbr_test_logs("*** Storing index (gen %lu)", directory->generation);

	_index_request_start();

	ret = fbr_index_write(fs, directory, directory->previous);
	fbr_test_ERROR(ret, "fbr_index_write() failed");

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	_index_validate_directory(directory);

	_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Making changes v3");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->previous != old_directory)
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_directory_copy(fs, directory->previous, directory);
	directory->generation++;
	_INDEX_GENERATION++;
	_index_add_file(fs, directory);

	fbr_test_logs("*** Storing index (gen %lu) FAIL", directory->generation);

	_index_request_start();

	ret = fbr_index_write(fs, directory, old_directory);
	fbr_test_ASSERT(ret, "fbr_index_write() did NOT fail");
	assert(directory->state == FBR_DIRSTATE_LOADING);

	_index_request_finish();

	fbr_test_logs("*** Storing index (gen %lu) FAIL v2", directory->generation);

	_index_request_start();

	ret = fbr_index_write(fs, directory, NULL);
	fbr_test_ASSERT(ret, "fbr_index_write() did NOT fail");
	assert(directory->state == FBR_DIRSTATE_LOADING);

	_index_request_finish();

	fbr_test_logs("*** Storing index (gen %lu) RETRY", directory->generation);

	_index_request_start();

	fbr_directory_ok(directory->previous);
	ret = fbr_index_write(fs, directory, directory->previous);
	fbr_test_ERROR(ret, "fbr_index_write() failed");

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	_index_validate_directory(directory);

	_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Releasing directory v2");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index v2 (duplicate error)");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous); // We are olding old_directory...
	assert(directory->state == FBR_DIRSTATE_LOADING);

	_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_ERROR);

	_index_request_finish();
	fbr_dindex_release(fs, &directory);
	fbr_dindex_release(fs, &old_directory);

	fbr_test_logs("*** Releasing directory v3");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** Loading index v3");

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	_index_validate_directory(directory);

	_index_request_finish();
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
