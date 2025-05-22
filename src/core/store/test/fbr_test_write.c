/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "fbr_test_store_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/store/test/fbr_dstore.h"

static const struct fbr_store_callbacks _WRITE_CALLBACKS = {
	.chunk_read_f = fbr_dstore_chunk_read,
	.chunk_delete_f = fbr_dstore_chunk_delete,
	.wbuffer_write_f = fbr_dstore_wbuffer_write,
	.wbuffers_flush_f = fbr_test_fs_rw_wbuffers_flush,
	.index_write_f = fbr_dstore_index_root_write,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

extern int _DEBUG_WBUFFER_ALLOC_SIZE;

static size_t _WBUFFER_SIZE;
static size_t _FILE_SIZE;

static void
_init(void)
{
	_WBUFFER_SIZE = 250;
	_FILE_SIZE = 10 * 1000;
}

static void
_write_test(void)
{
	assert_zero(_FILE_SIZE % _WBUFFER_SIZE);

	struct fbr_test_context *test_ctx = fbr_test_get_ctx();

	fbr_dstore_init(test_ctx);

	struct fbr_fs *fs = fbr_test_fuse_mock(test_ctx);
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, &_WRITE_CALLBACKS);

	_DEBUG_WBUFFER_ALLOC_SIZE = _WBUFFER_SIZE;

	fbr_test_logs("*** Allocating root directory");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;

	struct fbr_path_name name;
	fbr_path_name_init(&name, "file_write_store");
	struct fbr_file *file = fbr_file_alloc(fs, directory, &name);
	file->state = FBR_FILE_OK;

	fbr_test_index_request_start();

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, directory, NULL, NULL, NULL, FBR_INDEX_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	fbr_dindex_release(fs, &directory);

	fbr_test_index_request_finish();

	fbr_test_logs("*** Initial fio");

	fbr_test_index_request_start();

	fbr_inode_add(fs, file);
	struct fbr_fio *fio = fbr_fio_alloc(fs, file);

	char buffer[100];
	assert_zero(_FILE_SIZE % sizeof(buffer));
	memset(buffer, 0, sizeof(buffer));

	size_t offset = 0;
	while (offset < _FILE_SIZE) {
		fbr_wbuffer_write(fs, fio, offset, buffer, sizeof(buffer));
		if (offset % 1000 == 0) {
			ret = fbr_wbuffer_flush(fs, fio);
			assert_zero(ret);
		}
		offset += sizeof(buffer);
	}
	assert(offset == _FILE_SIZE);
	assert(file->size == _FILE_SIZE);

	ret = fbr_wbuffer_flush(fs, fio);
	assert_zero(ret);

	fbr_fio_release(fs, fio);

	fbr_test_index_request_finish();

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
}

void
fbr_cmd_store_write(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_init();

	_write_test();

	fbr_test_logs("store_write done");
}
