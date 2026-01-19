/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_callback.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

void
fbr_cmd_merge_2fs_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_fuse_mock(ctx);
	fbr_test_cstore_init(ctx);

	struct fbr_fs *fs_1 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_1);
	fbr_fs_set_store(fs_1, FBR_CSTORE_DEFAULT_CALLBACKS);

	struct fbr_fs *fs_2 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_2);
	fbr_fs_set_store(fs_2, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_logs("*** Allocating dir_fs1 and file.merge2");

	struct fbr_directory *dir_fs1 = fbr_directory_root_alloc(fs_1);
	fbr_directory_ok(dir_fs1);
	assert_zero(dir_fs1->previous);
	assert(dir_fs1->state == FBR_DIRSTATE_LOADING);
	dir_fs1->generation = 1;

	struct fbr_path_name filename2;
	fbr_path_name_init(&filename2, "file.merge2");
	struct fbr_file *file2 = fbr_file_alloc(fs_1, dir_fs1, &filename2);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_INIT);
	assert_zero(file2->size);
	file2->generation = 1;
	file2->state = FBR_FILE_OK;

	fbr_test_logs("*** Storing dir_fs1 (gen %lu)", dir_fs1->generation);

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, dir_fs1, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs_1, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write(fs_1) failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs_1, dir_fs1, FBR_DIRSTATE_OK);
	assert(dir_fs1->file_count == 1);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Loading dir_fs2");

	struct fbr_directory *dir_fs2 = fbr_directory_root_alloc(fs_2);
	fbr_directory_ok(dir_fs2);
	assert_zero(dir_fs2->previous);
	assert(dir_fs2->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_2, dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 1);
	assert(dir_fs2->file_count == 1);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Write file.merge1 on dir_fs1 (10 bytes)");

	dir_fs1 = fbr_dindex_take(fs_1, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs1);
	assert(dir_fs1->state == FBR_DIRSTATE_OK);
	assert(dir_fs1->generation == 1);
	assert(dir_fs1->file_count == 1);

	struct fbr_path_name filename1;
	fbr_path_name_init(&filename1, "file.merge1");
	struct fbr_file *file1 = fbr_file_alloc_new(fs_1, dir_fs1, &filename1);
	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_INIT);
	assert_zero(file1->size);
	file1->mode = S_IFREG | 0444;

	struct fbr_fio *fio = fbr_fio_alloc(fs_1, file1, 0);
	fbr_wbuffer_write(fs_1, fio, 0, "1234567890", 10);
	ret = fbr_wbuffer_flush_fio(fs_1, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_1) failed");
	fbr_fio_release(fs_1, fio);

	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_OK);
	assert(file1->size == 10);
	assert(file1->generation == 1);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Write file.merge1 on dir_fs2 (5 bytes)");

	dir_fs2 = fbr_dindex_take(fs_2, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 1);
	assert(dir_fs2->file_count == 1);

	file1 = fbr_file_alloc_new(fs_2, dir_fs2, &filename1);
	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_INIT);
	assert_zero(file1->size);
	assert_zero(file1->mode);

	fio = fbr_fio_alloc(fs_2, file1, 0);
	fbr_wbuffer_write(fs_2, fio, 0, "ABCDE", 5);
	ret = fbr_wbuffer_flush_fio(fs_2, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_2) failed");
	fbr_fio_release(fs_2, fio);

	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_OK);
	assert(file1->size == 10);
	assert(file1->generation == 2);
	assert(file1->mode == (S_IFREG | 0444));

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Write file.merge2 on dir_fs2 (20 bytes)");

	dir_fs2 = fbr_dindex_take(fs_2, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 3);
	assert(dir_fs2->file_count == 2);

	file2 = fbr_directory_find_file(dir_fs2, filename2.name, filename2.length);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->generation == 1);
	assert_zero(file2->size);
	assert_zero(file2->uid);
	assert_zero(file2->gid);
	file2->uid = 987654;
	file2->gid = 123456;

	fio = fbr_fio_alloc(fs_2, file2, 0);
	fbr_wbuffer_write(fs_2, fio, 0, "ABCDEFGHIJKLMOPQRST", 20);
	ret = fbr_wbuffer_flush_fio(fs_2, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_2) failed");
	fbr_fio_release(fs_2, fio);

	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->size == 20);
	assert(file2->generation == 2);

	fbr_dindex_release(fs_2, &dir_fs2);

	fbr_test_logs("*** Write file.merge2 on dir_fs1 (10 bytes)");

	dir_fs1 = fbr_dindex_take(fs_1, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(dir_fs1);
	assert(dir_fs1->state == FBR_DIRSTATE_OK);
	assert(dir_fs1->generation == 2);
	assert(dir_fs1->file_count == 2);

	file2 = fbr_directory_find_file(dir_fs1, filename2.name, filename2.length);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->generation == 1);
	assert_zero(file2->size);
	assert_zero(file2->uid);
	assert_zero(file2->gid);

	fio = fbr_fio_alloc(fs_1, file2, 0);
	fbr_wbuffer_write(fs_1, fio, 0, "1234567890", 10);
	ret = fbr_wbuffer_flush_fio(fs_1, fio);
	fbr_test_ERROR(ret, "fbr_wbuffer_flush_fio(fs_1) failed");
	fbr_fio_release(fs_1, fio);

	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->size == 20);
	assert(file2->generation == 3);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Loading dir_fs1 and validate");

	dir_fs1 = fbr_directory_root_alloc(fs_1);
	fbr_directory_ok(dir_fs1);
	assert(dir_fs1->previous);
	assert(dir_fs1->previous->generation == 5);
	assert(dir_fs1->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_1, dir_fs1);
	assert(dir_fs1->state == FBR_DIRSTATE_ERROR);
	fbr_dindex_release(fs_1, &dir_fs1);

	dir_fs1 = fbr_dindex_take(fs_1, FBR_DIRNAME_ROOT, 0);
	assert(dir_fs1->state == FBR_DIRSTATE_OK);
	assert(dir_fs1->generation == 5);
	assert(dir_fs1->file_count == 2);

	file1 = fbr_directory_find_file(dir_fs1, filename1.name, filename1.length);
	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_OK);
	assert(file1->size == 10);
	assert(file1->generation == 2);

	char buffer[100];
	size_t bytes = fbr_test_fs_read(fs_1, file1, 0, buffer, sizeof(buffer));
	fbr_test_ASSERT(bytes == 10, "Found %zu", bytes);
	fbr_test_ASSERT(!memcmp(buffer, "ABCDE67890", bytes), "Body mismatch '%.*s'", 10, buffer);

	file2 = fbr_directory_find_file(dir_fs1, filename2.name, filename2.length);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->size == 20);
	assert(file2->generation == 3);

	bytes = fbr_test_fs_read(fs_1, file2, 0, buffer, sizeof(buffer));
	fbr_test_ASSERT(bytes == 20, "Found %zu", bytes);
	fbr_test_ASSERT(!memcmp(buffer, "1234567890KLMOPQRST", bytes), "Body mismatch '%.*s'",
		20, buffer);

	fbr_dindex_release(fs_1, &dir_fs1);

	fbr_test_logs("*** Loading dir_fs2 and validate");

	dir_fs2 = fbr_directory_root_alloc(fs_2);
	fbr_directory_ok(dir_fs2);
	assert(dir_fs2->previous);
	assert(dir_fs2->previous->generation == 4);
	assert(dir_fs2->state == FBR_DIRSTATE_LOADING);

	fbr_index_read(fs_2, dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);
	assert(dir_fs2->generation == 5);
	assert(dir_fs2->file_count == 2);

	file1 = fbr_directory_find_file(dir_fs2, filename1.name, filename1.length);
	fbr_file_ok(file1);
	assert(file1->state == FBR_FILE_OK);
	assert(file1->size == 10);
	assert(file1->generation == 2);

	bytes = fbr_test_fs_read(fs_2, file1, 0, buffer, sizeof(buffer));
	fbr_test_ASSERT(bytes == 10, "Found %zu", bytes);
	fbr_test_ASSERT(!memcmp(buffer, "ABCDE67890", bytes), "Body mismatch '%.*s'", 10, buffer);

	file2 = fbr_directory_find_file(dir_fs2, filename2.name, filename2.length);
	fbr_file_ok(file2);
	assert(file2->state == FBR_FILE_OK);
	assert(file2->size == 20);
	assert(file2->generation == 3);

	bytes = fbr_test_fs_read(fs_2, file2, 0, buffer, sizeof(buffer));
	fbr_test_ASSERT(bytes == 20, "Found %zu", bytes);
	fbr_test_ASSERT(!memcmp(buffer, "1234567890KLMOPQRST", bytes), "Body mismatch '%.*s'",
		20, buffer);

	fbr_dindex_release(fs_2, &dir_fs2);

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
	fbr_test_ASSERT(fs_1->stats.flush_conflicts == 1, "zero");
	fbr_test_ASSERT(fs_1->stats.merges == 1, "zero");

	fbr_fs_free(fs_1);

	fbr_test_logs("*** Cleanup fs_2");

	fbr_fs_release_all(fs_2, 1);

	fbr_test_fs_stats(fs_2);
	fbr_test_fs_inodes_debug(fs_2);
	fbr_test_fs_dindex_debug(fs_2);
	fbr_test_cstore_debug_0();

	fbr_test_ERROR(fs_2->stats.directories, "non zero");
	fbr_test_ERROR(fs_2->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_2->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_2->stats.files, "non zero");
	fbr_test_ERROR(fs_2->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_2->stats.file_refs, "non zero");
	fbr_test_ASSERT(fs_2->stats.flush_conflicts == 1, "zero");
	fbr_test_ASSERT(fs_2->stats.merges == 1, "zero");

	fbr_fs_free(fs_2);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "merge_2fs_test done");
}

void
fbr_cmd_merge_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file1, *file2;
	struct fbr_path_name name;
	struct fbr_chunk_list *chunks;
	struct fbr_chunk_list *removed = NULL;

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge1"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	fbr_body_chunk_add(fs, file1, 3, 200, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->size == 300);
	file2 = fbr_file_alloc_new(fs, root, &name);
	assert(fbr_test_fs_count_chunks(file2) == 0);
	assert(file2->size == 0);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(file1->size == 300);
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 1);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 2);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 3);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge2"));
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 0);
	assert(file1->size == 0);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 1, 0, 100);
	fbr_body_chunk_add(fs, file2, 2, 100, 100);
	fbr_body_chunk_add(fs, file2, 3, 200, 100);
	assert(fbr_test_fs_count_chunks(file2) == 3);
	assert(file2->size == 300);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(file1->size == 300);
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 1);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 2);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 3);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge3"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	fbr_body_chunk_add(fs, file1, 3, 200, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->size == 300);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 1, 0, 100);
	fbr_body_chunk_add(fs, file2, 2, 100, 100);
	fbr_body_chunk_add(fs, file2, 3, 200, 100);
	assert(fbr_test_fs_count_chunks(file2) == 3);
	assert(file2->size == 300);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(file1->size == 300);
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 1);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 2);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 3);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge4"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	fbr_body_chunk_add(fs, file1, 3, 200, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->size == 300);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 4, 0, 100);
	fbr_body_chunk_add(fs, file2, 5, 100, 100);
	fbr_body_chunk_add(fs, file2, 6, 200, 100);
	assert(fbr_test_fs_count_chunks(file2) == 3);
	assert(file2->size == 300);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 6);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 5));
	assert(file1->size == 300);
	chunks = fbr_body_chunk_range(file1, 0, file1->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file1");
	assert(chunks->length == 3);
	assert(chunks->list[0]->id == 4);
	assert(chunks->list[1]->id == 5);
	assert(chunks->list[2]->id == 6);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  file1:removed");
	assert(removed->length == 3);
	assert(removed->list[0]->id == 1);
	assert(removed->list[1]->id == 2);
	assert(removed->list[2]->id == 3);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge5"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	fbr_body_chunk_add(fs, file1, 3, 200, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 3);
	fbr_test_fs_get_chunk(file1, 1)->state = FBR_CHUNK_WBUFFER;
	assert(file1->size == 300);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 4, 0, 100);
	fbr_body_chunk_add(fs, file2, 5, 100, 100);
	fbr_body_chunk_add(fs, file2, 6, 200, 100);
	assert(fbr_test_fs_count_chunks(file2) == 3);
	assert(file2->size == 300);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 6);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 5));
	assert(file1->size == 300);
	chunks = fbr_body_chunk_range(file1, 0, file1->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file1");
	assert(chunks->length == 3);
	assert(chunks->list[0]->id == 4);
	assert(chunks->list[1]->id == 2);
	assert(chunks->list[2]->id == 6);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  file1:removed");
	assert(removed->length == 3);
	assert(removed->list[0]->id == 1);
	assert(removed->list[1]->id == 5);
	assert(removed->list[2]->id == 3);
	fbr_test_fs_get_chunk(file1, 2)->state = FBR_CHUNK_EMPTY;
	fbr_body_chunk_prune(fs, file1, removed);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 4);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 2);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 6);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge6"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 2);
	assert(file1->size == 200);
	fbr_test_fs_get_chunk(file1, 0)->state = FBR_CHUNK_WBUFFER;
	fbr_test_fs_get_chunk(file1, 1)->state = FBR_CHUNK_WBUFFER;
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 3, 0, 300);
	fbr_body_chunk_add(fs, file2, 4, 300, 100);
	assert(fbr_test_fs_count_chunks(file2) == 2);
	assert(file2->size == 400);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 4);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 3));
	assert(file1->size == 400);
	chunks = fbr_body_chunk_range(file1, 0, file1->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file1");
	assert(chunks->length == 4);
	assert(chunks->list[0]->id == 1);
	assert(chunks->list[1]->id == 2);
	assert(chunks->list[2]->id == 3);
	assert(chunks->list[3]->id == 4);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  file1:removed");
	assert(removed->length == 0);
	fbr_test_fs_get_chunk(file1, 0)->state = FBR_CHUNK_EMPTY;
	fbr_test_fs_get_chunk(file1, 1)->state = FBR_CHUNK_EMPTY;
	fbr_body_chunk_prune(fs, file1, removed);
	assert(fbr_test_fs_count_chunks(file1) == 4);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 3));
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 1);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 2);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 3);
	assert(fbr_test_fs_get_chunk(file1, 3)->id == 4);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge7"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	fbr_body_chunk_add(fs, file1, 3, 200, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->size == 300);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 4, 50, 450);
	assert(fbr_test_fs_count_chunks(file2) == 1);
	assert(file2->size == 500);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 4);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 3));
	assert(file1->size == 500);
	chunks = fbr_body_chunk_range(file1, 0, file1->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file1");
	assert(chunks->length == 2);
	assert(chunks->list[0]->id == 4);
	assert(chunks->list[1]->id == 1);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  file1:removed");
	assert(removed->length == 2);
	assert(removed->list[0]->id == 2);
	assert(removed->list[1]->id == 3);
	fbr_body_chunk_prune(fs, file1, removed);
	assert(fbr_test_fs_count_chunks(file1) == 2);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 1));
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 4);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 1);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge8"));
	fbr_body_chunk_add(fs, file1, 1, 100, 100);
	assert(fbr_test_fs_count_chunks(file1) == 1);
	assert(file1->size == 200);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 2, 0, 150);
	fbr_body_chunk_add(fs, file2, 3, 150, 10);
	fbr_body_chunk_append(fs, file2, 1, 100, 100, 0);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file2) == 3);
	assert(fbr_test_fs_get_chunk(file2, 0)->id == 2);
	assert(fbr_test_fs_get_chunk(file2, 1)->id == 3);
	assert(fbr_test_fs_get_chunk(file2, 2)->id == 1);
	assert(file2->size == 200);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(file1->size == 200);
	chunks = fbr_body_chunk_range(file1, 0, file1->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file1");
	assert(chunks->length == 3);
	assert(chunks->list[0]->id == 2);
	assert(chunks->list[1]->id == 3);
	assert(chunks->list[2]->id == 1);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  file1:removed");
	assert(removed->length == 0);
	fbr_body_chunk_prune(fs, file1, removed);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 2);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 3);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 1);
	fbr_file_free(fs, file1);

	file1 = fbr_file_alloc_new(fs, root, fbr_path_name_init(&name, "file_merge9"));
	fbr_body_chunk_add(fs, file1, 1, 0, 100);
	fbr_body_chunk_add(fs, file1, 2, 100, 100);
	fbr_body_chunk_add(fs, file1, 3, 200, 100);
	file1->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file1) == 3);
	fbr_test_fs_get_chunk(file1, 2)->state = FBR_CHUNK_WBUFFER;
	assert(file1->size == 300);
	file2 = fbr_file_alloc_new(fs, root, &name);
	fbr_body_chunk_add(fs, file2, 4, 0, 100);
	fbr_body_chunk_add(fs, file2, 5, 100, 100);
	fbr_body_chunk_add(fs, file2, 6, 200, 100);
	assert(fbr_test_fs_count_chunks(file2) == 3);
	assert(file2->size == 300);
	fbr_file_merge(fs, file2, file1);
	fbr_file_free(fs, file2);
	assert(fbr_test_fs_count_chunks(file1) == 6);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 5));
	assert(file1->size == 300);
	chunks = fbr_body_chunk_range(file1, 0, file1->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file1");
	assert(chunks->length == 3);
	assert(chunks->list[0]->id == 4);
	assert(chunks->list[1]->id == 5);
	assert(chunks->list[2]->id == 3);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  file1:removed");
	assert(removed->length == 3);
	assert(removed->list[0]->id == 1);
	assert(removed->list[1]->id == 2);
	assert(removed->list[2]->id == 6);
	fbr_test_fs_get_chunk(file1, 4)->state = FBR_CHUNK_EMPTY;
	fbr_body_chunk_prune(fs, file1, removed);
	assert(fbr_test_fs_count_chunks(file1) == 3);
	assert(file1->body.chunk_last == fbr_test_fs_get_chunk(file1, 2));
	assert(fbr_test_fs_get_chunk(file1, 0)->id == 4);
	assert(fbr_test_fs_get_chunk(file1, 1)->id == 5);
	assert(fbr_test_fs_get_chunk(file1, 2)->id == 3);
	fbr_file_free(fs, file1);

	fbr_chunk_list_free(removed);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "merge_test done");
}
