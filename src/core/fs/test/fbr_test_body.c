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

	struct fbr_path_name name;

	struct fbr_file *file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file1"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_ASSERT(_count_chunks(file) == 1, "Bad chunk count");
	fbr_ASSERT(_find_chunk(file, 0, 0), "Chunk missing");
	fbr_ASSERT(_get_chunk(file, 0), "Chunk missing");
	fbr_ASSERT(_find_chunk(file, 0, 0)->id == 1, "Wrong chunk");

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file2"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 0, 500);
	fbr_body_chunk_add(file, 3, 500, 500);
	assert(_count_chunks(file) == 2);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file3"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 3, 500, 500);
	fbr_body_chunk_add(file, 2, 0, 500);
	assert(_count_chunks(file) == 2);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file4"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 3, 500, 500);
	fbr_body_chunk_add(file, 2, 0, 499);
	assert(_count_chunks(file) == 3);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file5"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 0, 2000);
	assert(_count_chunks(file) == 1);
	assert(_get_chunk(file, 0)->id == 2);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file6"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 100, 100);
	fbr_body_chunk_add(file, 3, 600, 100);
	fbr_body_chunk_add(file, 4, 400, 200);
	fbr_body_chunk_add(file, 5, 150, 250);
	fbr_body_chunk_add(file, 6, 0, 200);
	fbr_body_chunk_add(file, 7, 600, 400);
	assert(_count_chunks(file) == 5);

	struct fbr_chunk_list *chunks = fbr_chunk_list_file(file, 0, 1000);
	fbr_chunk_list_debug(fs, chunks, "  chunks");
	assert(chunks->length == 5);

	struct fbr_chunk_list *reduced = fbr_chunk_list_reduce(chunks, 0, 1000);
	fbr_chunk_list_debug(fs, reduced, "  reduced");
	assert(reduced->length == 4);
	assert(reduced->list[0]->id == 6);
	assert(reduced->list[1]->id == 5);
	assert(reduced->list[2]->id == 4);
	assert(reduced->list[3]->id == 7);

	fbr_chunk_list_free(chunks);
	fbr_chunk_list_free(reduced);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_body done");
}
