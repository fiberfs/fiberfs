/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "core/fs/fbr_fs.h"
#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"

static size_t
_count_chunks(struct fbr_file *file)
{
	fbr_file_ok(file);

	const char *filename = fbr_path_get_file(&file->path, NULL);
	fbr_test_logs("* File: %s", filename);

	struct fbr_chunk *chunk = file->body.chunks;
	size_t count = 0;

	while (chunk) {
		fbr_chunk_ok(chunk);
		fbr_test_logs("  chunk[%zu]: id: %lu offset: %zu length: %zu",
			count, chunk->id, chunk->offset, chunk->length);
		count++;
		chunk = chunk->next;
	}

	return count;
}

static struct fbr_chunk *
_find_chunk(struct fbr_file *file, size_t offset, size_t size)
{
	fbr_file_ok(file);

	struct fbr_chunk *chunk = file->body.chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);

		if (fbr_chunk_in_offset(chunk, offset, size)) {
			return chunk;
		}

		chunk = chunk->next;
	}

	return NULL;
}

static struct fbr_chunk *
_get_chunk(struct fbr_file *file, size_t position)
{
	fbr_file_ok(file);

	struct fbr_chunk *chunk = file->body.chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);

		if (!position) {
			return chunk;
		}

		position--;
		chunk = chunk->next;
	}

	return NULL;
}

void
fbr_cmd_fs_test_body(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_chunk_list *chunks;
	struct fbr_chunk_list *removed = NULL;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file1"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_ASSERT(_count_chunks(file) == 1, "Bad chunk count");
	fbr_ASSERT(_find_chunk(file, 0, 0), "Chunk missing");
	fbr_ASSERT(_get_chunk(file, 0), "Chunk missing");
	fbr_ASSERT(_find_chunk(file, 0, 0)->id == 1, "Wrong chunk");
	fbr_ASSERT(file->size == 1000, "Bad file size");

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file2"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 0, 500);
	fbr_body_chunk_add(file, 3, 500, 500);
	assert(_count_chunks(file) == 3);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);
	assert(file->size == 1000);

	chunks = fbr_chunk_list_file(file, 0, file->size, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 2);
	assert(chunks->list[0]->id == 2);
	assert(chunks->list[1]->id == 3);
	fbr_chunk_list_free(chunks);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file3"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 3, 500, 500);
	fbr_body_chunk_add(file, 2, 0, 500);
	assert(_count_chunks(file) == 3);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);

	chunks = fbr_chunk_list_file(file, 0, file->size, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 2);
	assert(chunks->list[0]->id == 2);
	assert(chunks->list[1]->id == 3);
	fbr_chunk_list_free(chunks);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file4"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 3, 500, 500);
	fbr_body_chunk_add(file, 2, 0, 499);
	assert(_count_chunks(file) == 3);

	chunks = fbr_chunk_list_file(file, 0, file->size, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 3);
	fbr_chunk_list_free(chunks);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file5"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 0, 2000);
	assert(_count_chunks(file) == 2);
	assert(_get_chunk(file, 0)->id == 2);
	assert(file->size == 2000);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 1);
	assert(chunks->list[0]->id == 2);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 1);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file6"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 100, 100);
	fbr_body_chunk_add(file, 3, 600, 100);
	fbr_body_chunk_add(file, 4, 400, 200);
	fbr_body_chunk_add(file, 5, 150, 250);
	fbr_body_chunk_add(file, 6, 0, 200);
	fbr_body_chunk_add(file, 7, 600, 400);
	assert(_count_chunks(file) == 7);
	assert(file->size == 1000);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 4);
	assert(chunks->list[0]->id == 6);
	assert(chunks->list[1]->id == 5);
	assert(chunks->list[2]->id == 4);
	assert(chunks->list[3]->id == 7);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 3);
	assert(removed->list[0]->id == 2);
	assert(removed->list[1]->id == 3);
	assert(removed->list[2]->id == 1);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file7"));
	fbr_body_chunk_add(file, 1, 0, 100);
	fbr_body_chunk_add(file, 2, 50, 25);
	fbr_body_chunk_add(file, 3, 25, 25);
	fbr_body_chunk_add(file, 4, 0, 25);
	fbr_body_chunk_add(file, 5, 75, 25);
	assert(_count_chunks(file) == 5);
	assert(file->size == 100);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 4);
	assert(chunks->list[0]->id == 4);
	assert(chunks->list[1]->id == 3);
	assert(chunks->list[2]->id == 2);
	assert(chunks->list[3]->id == 5);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 1);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file8"));
	fbr_body_chunk_add(file, 1, 0, 100);
	fbr_body_chunk_add(file, 2, 100, 100);
	fbr_body_chunk_add(file, 3, 200, 100);
	fbr_body_chunk_add(file, 4, 300, 100);
	fbr_body_chunk_add(file, 5, 400, 100);
	fbr_body_chunk_add(file, 6, 500, 100);
	fbr_body_chunk_add(file, 7, 300, 200);
	assert(_count_chunks(file) == 7);
	assert(file->size == 600);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 5);
	assert(chunks->list[0]->id == 1);
	assert(chunks->list[1]->id == 2);
	assert(chunks->list[2]->id == 3);
	assert(chunks->list[3]->id == 7);
	assert(chunks->list[4]->id == 6);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 2);
	assert(removed->list[0]->id == 4);
	assert(removed->list[1]->id == 5);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file9"));
	fbr_body_chunk_add(file, 1, 0, 300);
	fbr_body_chunk_add(file, 2, 0, 100);
	fbr_body_chunk_add(file, 3, 100, 100);
	fbr_body_chunk_add(file, 4, 200, 100);
	fbr_body_chunk_add(file, 5, 0, 300);
	assert(_count_chunks(file) == 5);
	assert(_get_chunk(file, 0)->id == 5);
	assert(_get_chunk(file, 1)->id == 2);
	assert(_get_chunk(file, 2)->id == 3);
	assert(_get_chunk(file, 3)->id == 4);
	assert(_get_chunk(file, 4)->id == 1);
	assert(file->size == 300);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 1);
	assert(chunks->list[0]->id == 5);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 4);
	assert(removed->list[0]->id == 2);
	assert(removed->list[1]->id == 3);
	assert(removed->list[2]->id == 4);
	assert(removed->list[3]->id == 1);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file10"));
	fbr_body_chunk_add(file, 1, 0, 500);
	fbr_body_chunk_add(file, 2, 0, 100);
	fbr_body_chunk_add(file, 3, 100, 100);
	fbr_body_chunk_add(file, 4, 200, 111);
	fbr_body_chunk_add(file, 5, 10, 300);
	assert(_count_chunks(file) == 5);
	assert(_get_chunk(file, 0)->id == 5);
	assert(_get_chunk(file, 1)->id == 2);
	assert(_get_chunk(file, 2)->id == 3);
	assert(_get_chunk(file, 3)->id == 4);
	assert(_get_chunk(file, 4)->id == 1);
	assert(file->size == 500);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 4);
	assert(chunks->list[0]->id == 5);
	assert(chunks->list[1]->id == 2);
	assert(chunks->list[2]->id == 4);
	assert(chunks->list[3]->id == 1);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 3);

	fbr_chunk_list_free(removed);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_body done");
}
