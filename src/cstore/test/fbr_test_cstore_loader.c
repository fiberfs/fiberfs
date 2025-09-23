/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "fbr_test_cstore_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

extern struct fbr_cstore *_CSTORE;

void
fbr_cmd_cstore_loader_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** Allocating fs, root, and file");

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_init(ctx);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert_zero(root->previous);
	assert(root->state == FBR_DIRSTATE_LOADING);
	root->generation = 1;

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, root, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, "File");
	struct fbr_file *file = fbr_file_alloc_new(fs, root, &filename);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_INIT);
	file->mode = S_IFREG;

	struct fbr_fio *fio = fbr_fio_alloc(fs, file, 0);
	fbr_fio_ok(fio);
	char *file_contents = "File Contents.";
	fbr_wbuffer_write(fs, fio, 0, file_contents, 14);
	ret = fbr_wbuffer_flush_fio(fs, fio);
	assert_zero(ret);
	fbr_fio_release(fs, fio);
	assert(file->state == FBR_FILE_OK);
	assert(file->generation == 1);
	assert(file->size == 14);

	fbr_dindex_release(fs, &root);

	fbr_test_logs("*** Cleanup 1");

	//fbr_fs_release_all(fs, 1);
	//fbr_test_fs_stats(fs);
	fbr_test_cstore_debug();
	assert(_CSTORE->entries == 3);
	fbr_fs_free(fs);

	fbr_test_logs("*** Sleep %f", FBR_CSTORE_LOAD_TIME_BUFFER);
	fbr_sleep_ms(FBR_CSTORE_LOAD_TIME_BUFFER * 1010);

	fbr_test_logs("*** Allocating fs again");

	fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_reload(ctx);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_logs("*** Read root");

	root = fbr_directory_load(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert(root->file_count == 1);

	file = fbr_directory_find_file(root, filename.name, filename.length);
	fbr_file_ok(file);
	assert(file->size == 14);
	char buffer[15];
	size_t bytes = fbr_test_fs_read(fs, file, 0, buffer, sizeof(buffer));
	assert(bytes == 14);
	buffer[14] = '\0';
	assert_zero(strcmp(buffer, file_contents));

	fbr_test_logs("*** %s: '%s'", filename.name, buffer);

	fbr_dindex_release(fs, &root);

	fbr_test_logs("*** Cleanup 2");

	fbr_test_cstore_debug();
	assert(_CSTORE->entries == 3);

	size_t loaded = _CSTORE->loaded + _CSTORE->lazy_loaded;
	int checks = 40;
	while (loaded < 3 && checks) {
		fbr_test_sleep_ms(25);
		loaded = _CSTORE->loaded + _CSTORE->lazy_loaded;
		checks--;
	}
	fbr_test_logs("loaded: %zu (%zu+%zu)", loaded, _CSTORE->loaded, _CSTORE->lazy_loaded);
	fbr_ASSERT(loaded == 3, "loaded: %lu lazy: %lu", _CSTORE->loaded, _CSTORE->lazy_loaded);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_loader_test done");
}
