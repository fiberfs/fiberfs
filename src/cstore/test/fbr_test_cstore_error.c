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

extern struct fbr_cstore *_CSTORE;

void
fbr_cmd_cstore_error_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** Allocating fs and root directory and file stubs");

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_init_loader(ctx);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	struct fbr_request *request = fbr_request_alloc(NULL, __func__);

	assert(_CSTORE->loader.start_time);

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;

	for (size_t i = 1; i <= 5; i++) {
		char buffer[32];
		fbr_bprintf(buffer, "file_%zu", i);
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

	struct fbr_cstore_hashpath hashpath;
	struct fbr_cstore *cstore = fbr_cstore_find();
	fbr_cstore_ok(cstore);
	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file_1, chunk->id, chunk->offset);
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	fbr_test_logs("*** file_1 chunk: '%s'", hashpath.path);
	assert(fbr_sys_exists(hashpath.path));
	ret = unlink(hashpath.path);
	assert_zero(ret);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	fbr_test_logs("*** file_1 meta: '%s'", hashpath.path);
	assert(fbr_sys_exists(hashpath.path));

	fio = fbr_fio_alloc(fs, file_1, 1);
	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, 0, file_1->size);
	assert_zero(vector);
	fbr_fio_release(fs, fio);

	int max = 40;
	while (fbr_sys_exists(hashpath.path) && max) {
		fbr_test_sleep_ms(25);
		max--;
	}
	assert_zero(fbr_sys_exists(hashpath.path));
	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	assert_zero(entry);

	fbr_test_logs("*** Write file_1 again error");

	fio = fbr_fio_alloc(fs, file_1, 0);
	fbr_fio_ok(fio);
	fbr_wbuffer_write(fs, fio, 0, "write1 again (2)", 16);
	struct fbr_wbuffer *wbuffer = fio->wbuffers;
	fbr_wbuffer_ok(wbuffer);
	assert_zero(wbuffer->next);

	hash = fbr_cstore_hash_chunk(cstore, file_1, wbuffer->id, wbuffer->offset);
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	fbr_test_logs("*** file_1 new chunk: '%s'", hashpath.path);
	ret = fbr_sys_mkdirs(hashpath.path);
	assert_zero(ret);
	int fd = open(hashpath.path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	assert(fd > 0);
	assert_zero(close(fd));

	ret = fbr_wbuffer_flush_fio(fs, fio);
	assert(ret == EIO);
	fbr_wbuffers_reset(fs, fio);
	fbr_fio_release(fs, fio);
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** mkdir dir2");

	struct fbr_directory *root = fbr_dindex_take(fs, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert(root->generation == 2);

	// Alloc root dir2 file
	struct fbr_path_name dir2name;
	fbr_path_name_init(&dir2name, "dir2");
	struct fbr_file *dir2file = fbr_file_alloc_new(fs, root, &dir2name);
	assert_dev(dir2file->state == FBR_FILE_INIT);
	dir2file->mode = S_IFDIR;
	fbr_inode_add(fs, dir2file);
	fbr_inode_t dir2inode = dir2file->inode;

	// Write empty index
	struct fbr_directory *dir2 = fbr_directory_alloc(fs, &dir2name, dir2inode);
	fbr_directory_ok(dir2);
	assert(dir2->state == FBR_DIRSTATE_LOADING);
	dir2->generation = 1;
	fbr_index_data_init(fs, &index_data, dir2, NULL, NULL, NULL, FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	assert_zero(ret);
	fbr_directory_set_state(fs, dir2, FBR_DIRSTATE_OK);
	fbr_index_data_free(&index_data);
	fbr_dindex_release(fs, &dir2);

	// Flush root
	assert(fs->store);
	assert_zero(fs->store->optional.directory_flush_f);
	ret = fbr_directory_flush(fs, dir2file, NULL, FBR_FLUSH_NONE);
	assert_zero(ret);
	assert(dir2file->state == FBR_FILE_OK);

	fbr_inode_release(fs, &dir2file);
	fbr_dindex_release(fs, &root);

	fbr_test_logs("*** Write index error on dir2");

	dir2 = fbr_directory_alloc(fs, &dir2name, dir2inode);
	fbr_directory_ok(dir2);
	assert(dir2->state == FBR_DIRSTATE_LOADING);
	fbr_directory_ok(dir2->previous);
	assert(dir2->previous->generation == 1);
	dir2->generation = 2;

	hash = fbr_cstore_hash_index(cstore, dir2);
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	fbr_test_logs("*** dir2 new index: '%s'", hashpath.path);
	ret = fbr_sys_mkdirs(hashpath.path);
	assert_zero(ret);
	fd = open(hashpath.path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	assert(fd > 0);
	assert_zero(close(fd));

	fbr_index_data_init(fs, &index_data, dir2, dir2->previous, NULL, NULL, FBR_FLUSH_NONE);
	ret = fbr_index_write(fs, &index_data);
	assert(ret);
	fbr_directory_set_state(fs, dir2, FBR_DIRSTATE_ERROR);
	fbr_index_data_free(&index_data);
	fbr_dindex_release(fs, &dir2);

	fbr_test_logs("*** Read index error on dir2");

	dir2 = fbr_dindex_take(fs, &dir2name, 0);
	fbr_directory_ok(dir2);
	assert(dir2->generation == 1);
	assert_zero(dir2->previous);
	fbr_dindex_release(fs, &dir2);

	// Generation match...
	dir2 = fbr_directory_alloc(fs, &dir2name, dir2inode);
	fbr_directory_ok(dir2);
	assert(dir2->state == FBR_DIRSTATE_LOADING);
	fbr_directory_ok(dir2->previous);
	assert(dir2->previous->generation == 1);
	fbr_index_read(fs, dir2);
	assert(dir2->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &dir2);

	hash = fbr_cstore_hash_root(cstore, &dir2name);
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	fbr_test_logs("*** dir2 root: '%s'", hashpath.path);
	assert(fbr_sys_exists(hashpath.path));
	ret = unlink(hashpath.path);
	assert_zero(ret);

	// dir2 root error
	dir2 = fbr_directory_alloc(fs, &dir2name, dir2inode);
	fbr_directory_ok(dir2);
	assert(dir2->state == FBR_DIRSTATE_LOADING);
	fbr_directory_ok(dir2->previous);
	assert(dir2->previous->generation == 1);
	fbr_index_read(fs, dir2);
	assert(dir2->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs, &dir2);

	fbr_test_logs("*** Cleanup");

	fbr_fs_release_all(fs, 1);
	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);
	fbr_test_cstore_debug(_CSTORE);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");
	assert(fbr_test_cstore_stat_roots() == 2);
	assert(fbr_test_cstore_stat_indexes() == 2);
	assert_zero(_CSTORE->stats.loaded);
	assert_zero(_CSTORE->stats.lazy_loaded);

	fbr_request_free(request);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_error_test done");
}
