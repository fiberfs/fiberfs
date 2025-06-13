/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

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

size_t
fbr_test_fs_count_chunks(struct fbr_file *file)
{
	return _count_chunks(file);
}

struct fbr_chunk *
fbr_test_fs_get_chunk(struct fbr_file *file, size_t position)
{
	return _get_chunk(file, position);
}

void
fbr_cmd_fs_test_body(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fs_alloc();

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_chunk_list *chunks;
	struct fbr_chunk_list *removed = NULL;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file1"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	file->state = FBR_FILE_OK;
	fbr_ASSERT(_count_chunks(file) == 1, "Bad chunk count");
	fbr_ASSERT(_find_chunk(file, 0, 0), "Chunk missing");
	fbr_ASSERT(_get_chunk(file, 0), "Chunk missing");
	fbr_ASSERT(_find_chunk(file, 0, 0)->id == 1, "Wrong chunk");
	fbr_ASSERT(file->size == 1000, "Bad file size");

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	fbr_ASSERT(chunks->length == 1, "Bad file chunks count");
	fbr_ASSERT(chunks->list[0]->id == 1, "Wrong file chunk");
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	fbr_ASSERT(removed->length == 0, "Wrong removed length");

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file2"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	fbr_body_chunk_add(fs, file, 2, 0, 500);
	fbr_body_chunk_add(fs, file, 3, 500, 500);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 3);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);
	assert(file->size == 1000);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 2);
	assert(chunks->list[0]->id == 2);
	assert(chunks->list[1]->id == 3);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 1);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file3"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	fbr_body_chunk_add(fs, file, 3, 500, 500);
	fbr_body_chunk_add(fs, file, 2, 0, 500);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 3);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);

	chunks = fbr_body_chunk_range(file, 0, file->size, NULL, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 2);
	assert(chunks->list[0]->id == 2);
	assert(chunks->list[1]->id == 3);
	fbr_chunk_list_free(chunks);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file4"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	fbr_body_chunk_add(fs, file, 3, 500, 500);
	fbr_body_chunk_add(fs, file, 2, 0, 499);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 3);

	chunks = fbr_body_chunk_range(file, 0, file->size, NULL, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 3);
	fbr_chunk_list_free(chunks);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file5"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	fbr_body_chunk_add(fs, file, 2, 0, 2000);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 2);
	assert(_get_chunk(file, 0)->id == 2);
	assert(file->size == 2000);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 1);
	assert(chunks->list[0]->id == 2);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 1);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file6"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	fbr_body_chunk_add(fs, file, 2, 100, 100);
	fbr_body_chunk_add(fs, file, 3, 600, 100);
	fbr_body_chunk_add(fs, file, 4, 400, 200);
	fbr_body_chunk_add(fs, file, 5, 150, 250);
	fbr_body_chunk_add(fs, file, 6, 0, 200);
	fbr_body_chunk_add(fs, file, 7, 600, 400);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 7);
	assert(file->size == 1000);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
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
	fbr_body_chunk_add(fs, file, 1, 0, 100);
	fbr_body_chunk_add(fs, file, 2, 50, 25);
	fbr_body_chunk_add(fs, file, 3, 25, 25);
	fbr_body_chunk_add(fs, file, 4, 0, 25);
	fbr_body_chunk_add(fs, file, 5, 75, 25);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 5);
	assert(file->size == 100);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
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
	fbr_body_chunk_add(fs, file, 1, 0, 100);
	fbr_body_chunk_add(fs, file, 2, 100, 100);
	fbr_body_chunk_add(fs, file, 3, 200, 100);
	fbr_body_chunk_add(fs, file, 4, 300, 100);
	fbr_body_chunk_add(fs, file, 5, 400, 100);
	fbr_body_chunk_add(fs, file, 6, 500, 100);
	fbr_body_chunk_add(fs, file, 7, 300, 200);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 7);
	assert(file->size == 600);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
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
	fbr_body_chunk_add(fs, file, 1, 0, 300);
	fbr_body_chunk_add(fs, file, 2, 0, 100);
	fbr_body_chunk_add(fs, file, 3, 100, 100);
	fbr_body_chunk_add(fs, file, 4, 200, 100);
	fbr_body_chunk_add(fs, file, 5, 0, 300);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 5);
	assert(_get_chunk(file, 0)->id == 5);
	assert(_get_chunk(file, 1)->id == 2);
	assert(_get_chunk(file, 2)->id == 3);
	assert(_get_chunk(file, 3)->id == 4);
	assert(_get_chunk(file, 4)->id == 1);
	assert(file->size == 300);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
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
	fbr_body_chunk_add(fs, file, 1, 0, 500);
	fbr_body_chunk_add(fs, file, 2, 0, 100);
	fbr_body_chunk_add(fs, file, 3, 100, 100);
	fbr_body_chunk_add(fs, file, 4, 200, 111);
	fbr_body_chunk_add(fs, file, 5, 10, 300);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 5);
	assert(_get_chunk(file, 0)->id == 5);
	assert(_get_chunk(file, 1)->id == 2);
	assert(_get_chunk(file, 2)->id == 3);
	assert(_get_chunk(file, 3)->id == 4);
	assert(_get_chunk(file, 4)->id == 1);
	assert(file->size == 500);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
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

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file11"));
	fbr_body_chunk_add(fs, file, 1, 0, 200);
	fbr_body_chunk_append(fs, file, 2, 100, 100);
	fbr_body_chunk_append(fs, file, 3, 200, 100);
	fbr_body_chunk_append(fs, file, 4, 300, 100);
	fbr_body_chunk_append(fs, file, 5, 400, 100);
	fbr_body_chunk_add(fs, file, 6, 0, 300);
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 6);
	assert(_get_chunk(file, 0)->id == 6);
	assert(_get_chunk(file, 1)->id == 1);
	assert(_get_chunk(file, 2)->id == 2);
	assert(_get_chunk(file, 3)->id == 3);
	assert(_get_chunk(file, 4)->id == 4);
	assert(_get_chunk(file, 5)->id == 5);
	assert(file->size == 500);

	_get_chunk(file, 0)->state = FBR_CHUNK_WBUFFER;
	_get_chunk(file, 1)->state = FBR_CHUNK_WBUFFER;
	_get_chunk(file, 5)->state = FBR_CHUNK_WBUFFER;

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 3);
	assert(chunks->list[0]->id == 6);
	assert(chunks->list[1]->id == 4);
	assert(chunks->list[2]->id == 5);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 3);
	assert(removed->list[0]->id == 1);
	assert(removed->list[1]->id == 2);
	assert(removed->list[2]->id == 3);

	struct fbr_wbuffer wbuffer1;
	fbr_ZERO(&wbuffer1);
	wbuffer1.magic = FBR_WBUFFER_MAGIC;
	wbuffer1.chunk = _get_chunk(file, 1);
	struct fbr_wbuffer wbuffer2;
	fbr_ZERO(&wbuffer2);
	wbuffer2.magic = FBR_WBUFFER_MAGIC;
	wbuffer2.chunk = _get_chunk(file, 5);

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, &wbuffer1);
	fbr_chunk_list_debug(fs, chunks, "  file_wbuf");
	assert(chunks->length == 3);
	assert(chunks->list[0]->id == 1);
	assert(chunks->list[1]->id == 3);
	assert(chunks->list[2]->id == 4);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed_wbuf");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 2);

	wbuffer1.next = &wbuffer2;

	chunks = fbr_body_chunk_range(file, 0, file->size, &removed, &wbuffer1);
	fbr_chunk_list_debug(fs, chunks, "  file_wbuf2");
	assert(chunks->length == 4);
	assert(chunks->list[0]->id == 1);
	assert(chunks->list[1]->id == 3);
	assert(chunks->list[2]->id == 4);
	assert(chunks->list[3]->id == 5);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed_wbuf2");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 2);

	_get_chunk(file, 0)->state = FBR_CHUNK_EMPTY;
	_get_chunk(file, 1)->state = FBR_CHUNK_EMPTY;
	_get_chunk(file, 5)->state = FBR_CHUNK_EMPTY;

	fbr_chunk_list_free(removed);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_body done");
}

static void
_test_body_chunk_gen(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	chunk->state = FBR_CHUNK_READY;
	chunk->data = (void*)chunk->id;

	fs->log("FETCH chunk id: %lu off: %zu len: %zu",
		chunk->id, chunk->offset, chunk->length);
}

static const struct fbr_store_callbacks _TEST_BODY_STORE_CALLBACKS = {
	.chunk_read_f = _test_body_chunk_gen
};

void
fbr_cmd_fs_test_body_fio(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fs_alloc();

	fbr_fs_set_store(fs, &_TEST_BODY_STORE_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_fio *fio;
	struct fbr_chunk_vector *vector;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file1"));
	fbr_body_chunk_add(fs, file, 1, 0, 1000);
	file->state = FBR_FILE_OK;
	fbr_ASSERT(_count_chunks(file) == 1, "Bad chunk count");
	fbr_ASSERT(_find_chunk(file, 0, 0), "Chunk missing");
	fbr_ASSERT(_get_chunk(file, 0), "Chunk missing");
	fbr_ASSERT(_find_chunk(file, 0, 0)->id == 1, "Wrong chunk");
	fbr_ASSERT(file->size == 1000, "Bad file size");

	fio = fbr_fio_alloc(fs, file, 1);
	vector = fbr_fio_vector_gen(fs, fio, 0, file->size);
	fbr_ASSERT(vector, "Bad vector");
	fbr_ASSERT(!fio->error, "fio error");
	fbr_ASSERT(vector->bufvec, "bufvec missing");
	fbr_ASSERT(vector->bufvec->count == 1, "Bad bufvec count");
	fbr_fio_vector_free(fs, fio, vector);
	fbr_fio_release(fs, fio);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file2"));
	for (size_t i = 0; i < 5; i++) {
		fbr_body_chunk_add(fs, file, i + 1, i * 1000, 1000);
	}
	file->state = FBR_FILE_OK;
	assert(_count_chunks(file) == 5);
	assert(file->size == 5000);

	fio = fbr_fio_alloc(fs, file, 1);
	vector = fbr_fio_vector_gen(fs, fio, 0, 1500);
	assert(vector->bufvec->count == 2);
	fbr_fio_vector_free(fs, fio, vector);
	vector = fbr_fio_vector_gen(fs, fio, 1500, 2500);
	assert(vector->bufvec->count == 3);
	fbr_fio_vector_free(fs, fio, vector);
	fbr_fio_release(fs, fio);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_body_fio done");
}

void
fbr_cmd_fs_test_body_hole(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_test_fs_alloc();

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_path_name name;
	struct fbr_file *file;
	struct fbr_fio *fio;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file1"));
	file->state = FBR_FILE_OK;
	fbr_ASSERT(_count_chunks(file) == 0, "Bad chunk count");
	fbr_ASSERT(file->size == 0, "Bad file size");

	fio = fbr_fio_alloc(fs, file, 0);

	char buffer[1000];
	memset(buffer, 1, sizeof(buffer));

	fbr_wbuffer_write(fs, fio, 30000, buffer, sizeof(buffer));

	for (size_t i = 0; i < 128; i++) {
		if (i % 2) {
			continue;
		}

		fbr_wbuffer_write(fs, fio, i * sizeof(buffer), buffer,
			sizeof(buffer));
	}

	int ret = fbr_wbuffer_flush_fio(fs, fio);
	assert(ret);

	size_t count = 0;
	size_t allocs = 0;

	struct fbr_wbuffer *wbuffer = fio->wbuffers;
	while (wbuffer) {
		assert(wbuffer->state == FBR_WBUFFER_WRITING);
		assert(wbuffer->buffer);
		assert(wbuffer->end == 1000);
		assert(wbuffer->size >= wbuffer->end);

		count++;
		if (!wbuffer->split) {
			allocs++;
		}

		int ret = memcmp(wbuffer->buffer, buffer, wbuffer->end);
		assert_zero(ret);

		wbuffer = wbuffer->next;
	}

	fbr_test_logs("HOLE count: %zu", count);
	fbr_test_logs("HOLE allocs: %zu", allocs);

	assert(count == 64);
	assert(allocs == 3);

	fbr_wbuffers_reset_lock(fs, fio);

	fbr_fio_release(fs, fio);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_body_hole done");
}
