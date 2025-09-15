/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <unistd.h>

#include "fiberfs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

#include "test/fbr_test.h"
#include "fbr_test_cstore_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static const struct fbr_store_callbacks _CSTORE_ERR_CALLBACKS = {
	.chunk_read_f = fbr_cstore_async_chunk_read,
	.chunk_delete_f = fbr_cstore_chunk_delete,
	.wbuffer_write_f = fbr_cstore_async_wbuffer_write,
	.directory_flush_f = fbr_directory_flush,
	.index_write_f = fbr_cstore_index_root_write,
	.index_read_f = fbr_cstore_index_read,
	.index_delete_f = fbr_cstore_index_delete,
	.root_read_f = fbr_cstore_root_read
};

void
fbr_cmd_cstore_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** Allocating fs and root directory and file stubs");

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_init(ctx);
	fbr_fs_set_store(fs, &_CSTORE_ERR_CALLBACKS);

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;

	for (size_t i = 1; i <= 5; i++) {
		char buffer[32];
		int ret = snprintf(buffer, sizeof(buffer), "file_%zu", i);
		assert(ret > 0 && (size_t)ret < sizeof(buffer));
		struct fbr_path_name filename;
		fbr_path_name_init(&filename, buffer);
		struct fbr_file *file = fbr_file_alloc(fs, directory, &filename);
		file->generation = 1;
		file->mode = S_IFREG;
		file->state = FBR_FILE_OK;
	}

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, directory, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	struct fbr_file *file_1 = fbr_directory_find_file(directory, "file_1", 6);
	fbr_file_ok(file_1);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Write file_1");

	struct fbr_fio *fio = fbr_fio_alloc(fs, file_1, 0);
	fbr_fio_ok(fio);
	fbr_wbuffer_write(fs, fio, 0, "write1", 6);
	ret = fbr_wbuffer_flush_fio(fs, fio);
	assert_zero(ret);
	fbr_fio_release(fs, fio);

	fbr_test_logs("*** Read chunk error on file_1");

	directory = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->generation == 2);
	assert(fbr_directory_find_file(directory, "file_1", 6) == file_1);
	struct fbr_chunk *chunk = file_1->body.chunks;
	assert_zero(chunk->next);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	char path[FBR_PATH_MAX];
	struct fbr_cstore *cstore = fbr_cstore_find();
	fbr_cstore_ok(cstore);
	fbr_hash_t hash = fbr_cstore_hash_chunk(fs, file_1, chunk->id, chunk->offset);
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	fbr_test_logs("*** file_1 chunk: '%s'", path);
	assert(fbr_sys_exists(path));
	ret = unlink(path);
	assert_zero(ret);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	fbr_test_logs("*** file_1 meta: '%s'", path);
	assert(fbr_sys_exists(path));

	fio = fbr_fio_alloc(fs, file_1, 1);
	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, 0, file_1->size);
	assert_zero(vector);
	fbr_fio_release(fs, fio);

	assert_zero(fbr_sys_exists(path));
	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	assert_zero(entry);

	fbr_test_logs("*** Write file_1 again");

	fio = fbr_fio_alloc(fs, file_1, 0);
	fbr_fio_ok(fio);
	fbr_wbuffer_write(fs, fio, 0, "write1 again (2)", 16);
	struct fbr_wbuffer *wbuffer = fio->wbuffers;
	fbr_wbuffer_ok(wbuffer);
	assert_zero(wbuffer->next);
	hash = fbr_cstore_hash_chunk(fs, file_1, wbuffer->id, wbuffer->offset);
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	fbr_test_logs("*** file_1 new chunk: '%s'", path);
	ret = fbr_sys_mkdirs(path);
	assert_zero(ret);
	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	assert(fd > 0);
	assert_zero(close(fd));
	ret = fbr_wbuffer_flush_fio(fs, fio);
	assert(ret == EIO);
	fbr_wbuffers_reset(fs, fio);
	fbr_fio_release(fs, fio);
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Cleanup");

	fbr_fs_release_all(fs, 1);
	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);
	fbr_test_cstore_debug();

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");
	assert(fbr_test_cstore_stat_roots() == 1);
	assert(fbr_test_cstore_stat_indexes() == 1);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_error done");
}
