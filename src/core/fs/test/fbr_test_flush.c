/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <errno.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

int fbr_flush(struct fbr_fs *fs, struct fbr_flush_data *flush_data_cmds);

static int _FLUSH_COUNT;
static struct fbr_flush_data _FLUSH_CMDS[2];

static int
_test_flush(struct fbr_fs *fs, struct fbr_flush_data *flush_data_cmds)
{
	fbr_fs_ok(fs);
	fbr_flush_data_ok(flush_data_cmds);
	assert_zero(flush_data_cmds->next);

	fbr_test_logs("*** Got flush command");

	if (!_FLUSH_COUNT) {
		memcpy(&_FLUSH_CMDS[0], flush_data_cmds, sizeof(*flush_data_cmds));
		_FLUSH_COUNT++;

		fbr_test_logs("*** flush 0 captured");

		return EBUSY;
	}

	assert(_FLUSH_COUNT == 1);

	_FLUSH_CMDS[0].next = flush_data_cmds;

	fbr_test_logs("*** sending flush 0 + 1");

	return fbr_flush(fs, &_FLUSH_CMDS[0]);
}

static struct fbr_store_callbacks _TEST_FLUSH_CALLBACKS;

void
fbr_cmd_fs_test_multi_flush(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);

	memcpy(&_TEST_FLUSH_CALLBACKS, FBR_CSTORE_DEFAULT_CALLBACKS, sizeof(_TEST_FLUSH_CALLBACKS));
	_TEST_FLUSH_CALLBACKS.optional.directory_flush_f = _test_flush;
	fbr_fs_set_store(fs, &_TEST_FLUSH_CALLBACKS);

	struct fbr_fs *fs_read = fbr_test_fs_mock(ctx);
	fbr_fs_ok(fs_read);
	fbr_test_cstore_bind(fs_read, 0);
	fbr_fs_set_store(fs_read, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_logs("*** Allocating root");

	fbr_test_fs_root_alloc(fs);

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert_zero(root->previous);
	assert(root->generation == 1);
	assert_zero(root->file_count);

	fbr_test_logs("*** Writing file1 (deferred flush)");

	struct fbr_path_name filename1;
	fbr_path_name_init(&filename1, "file.name1");
	struct fbr_file *file1 = fbr_file_alloc_new(fs, root, &filename1);
	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_INIT);
	assert_zero(file1->size);

	struct fbr_fio *fio1 = fbr_fio_alloc(fs, file1, 0);
	fbr_wbuffer_write(fs, fio1, 0, "111", 3);
	int ret = fbr_wbuffer_flush_fio(fs, fio1);
	assert(ret == EBUSY);

	fbr_test_logs("*** Writing file2 (combined flush)");

	struct fbr_path_name filename2;
	fbr_path_name_init(&filename2, "file.name2");
	struct fbr_file *file2 = fbr_file_alloc_new(fs, root, &filename2);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_INIT);
	assert_zero(file2->size);

	struct fbr_fio *fio2 = fbr_fio_alloc(fs, file2, 0);
	fbr_wbuffer_write(fs, fio2, 0, "two two", 7);
	ret = fbr_wbuffer_flush_fio(fs, fio2);
	assert_zero(ret);

	fbr_wbuffers_reset(fs, fio1);
	fbr_fio_release(fs, fio1);
	fbr_fio_release(fs, fio2);

	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_OK);
	assert(file1->size == 3);
	assert(file1->generation == 1);

	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->size == 7);
	assert(file2->generation == 1);

	fbr_dindex_release(fs, &root);

	fbr_fs_release_all(fs, 1);
	fbr_test_fs_stats(fs);
	fbr_test_cstore_debug(fs->cstore);

	assert(fs->stats.flushes == 1);
	assert(fs->stats.flush_errors == 1);
	assert(fs->cstore->stats.wr_indexes == 1);
	assert(fs->cstore->stats.wr_chunks == 2);

	assert_zero(fs->stats.directories);
	assert_zero(fs->stats.directories_dindex);
	assert_zero(fs->stats.directory_refs);
	assert_zero(fs->stats.files);
	assert_zero(fs->stats.files_inodes);
	assert_zero(fs->stats.file_refs);

	fbr_fs_free(fs);

	fbr_test_logs("*** Read files");

	root = fbr_directory_get(fs_read, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert(root->file_count == 2);

	file1 = fbr_directory_find_file(root, filename1.name, filename1.length);
	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_OK);
	assert(file1->size == 3);

	char buffer[32];
	size_t bytes = fbr_test_fs_read(fs_read, file1, 0, buffer, sizeof(buffer));
	assert(bytes == file1->size);
	assert_zero(memcmp(buffer, "111", bytes));

	file2 = fbr_directory_find_file(root, filename2.name, filename2.length);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->size == 7);

	bytes = fbr_test_fs_read(fs_read, file2, 0, buffer, sizeof(buffer));
	assert(bytes == file2->size);
	assert_zero(memcmp(buffer, "two two", bytes));

	fbr_dindex_release(fs_read, &root);
	fbr_fs_release_all(fs_read, 1);
	fbr_fs_free(fs_read);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_multi_flush done");
}
