/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

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

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	fbr_ASSERT(chunks->length == 1, "Bad file chunks count");
	fbr_ASSERT(chunks->list[0]->id == 1, "Wrong file chunk");
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	fbr_ASSERT(removed->length == 0, "Wrong removed length");

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file2"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_body_chunk_add(file, 2, 0, 500);
	fbr_body_chunk_add(file, 3, 500, 500);
	assert(_count_chunks(file) == 3);
	assert(_find_chunk(file, 0, 0)->id == 2);
	assert(_find_chunk(file, 500, 500)->id == 3);
	assert(file->size == 1000);

	chunks = fbr_chunk_list_file(file, 0, file->size, &removed);
	fbr_chunk_list_debug(fs, chunks, "  file");
	assert(chunks->length == 2);
	assert(chunks->list[0]->id == 2);
	assert(chunks->list[1]->id == 3);
	fbr_chunk_list_free(chunks);
	fbr_chunk_list_debug(fs, removed, "  removed");
	assert(removed->length == 1);
	assert(removed->list[0]->id == 1);

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
	.fetch_chunk_f = _test_body_chunk_gen
};

void
fbr_cmd_fs_test_body_fio(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;

	fbr_fs_set_store(fs, &_TEST_BODY_STORE_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_fio *fio;
	struct fbr_chunk_vector *vector;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file1"));
	fbr_body_chunk_add(file, 1, 0, 1000);
	fbr_ASSERT(_count_chunks(file) == 1, "Bad chunk count");
	fbr_ASSERT(_find_chunk(file, 0, 0), "Chunk missing");
	fbr_ASSERT(_get_chunk(file, 0), "Chunk missing");
	fbr_ASSERT(_find_chunk(file, 0, 0)->id == 1, "Wrong chunk");
	fbr_ASSERT(file->size == 1000, "Bad file size");

	fbr_inode_add(fs, file);
	fio = fbr_fio_alloc(fs, file);
	vector = fbr_fio_vector_gen(fs, fio, 0, file->size);
	fbr_ASSERT(vector, "Bad vector");
	fbr_ASSERT(!fio->error, "fio error");
	fbr_ASSERT(vector->bufvec, "bufvec missing");
	fbr_ASSERT(vector->bufvec->count == 1, "Bad bufvec count");
	fbr_fio_vector_free(fs, fio, vector);
	fbr_fio_release(fs, fio);

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file2"));
	for (size_t i = 0; i < 5; i++) {
		fbr_body_chunk_add(file, i + 1, i * 1000, 1000);
	}
	assert(_count_chunks(file) == 5);
	assert(file->size == 5000);

	fbr_inode_add(fs, file);
	fio = fbr_fio_alloc(fs, file);
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

#define _BODY_TEST_THREADS 10

static pthread_t _fetch_threads[_BODY_TEST_THREADS];
static int _fio_thread_id = -1;
static int _fetch_thread_id = -1;
static int _fetch_calls;

struct _thread_args {
	struct fbr_fs *fs;
	struct fbr_fio *fio;
	struct fbr_file *file;
	struct fbr_chunk *chunk;
};

static void *
_test_fetch_thread(void *arg)
{
	struct _thread_args *args = (struct _thread_args*)arg;
	struct fbr_fs *fs = args->fs;
	struct fbr_file *file = args->file;
	struct fbr_chunk *chunk = args->chunk;

	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_LOADING);

	free(args);

	chunk->data = (void*)chunk->id;

	int id = fbr_atomic_add(&_fetch_thread_id, 1);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	fbr_test_logs("FETCH thread: %d chunk: %lu", id, chunk->id);

	while (_fetch_thread_id < _BODY_TEST_THREADS - 1) {
		fbr_sleep_ms(0.1);
	}

	fbr_test_logs("FETCH synced: %d", id);

	fbr_sleep_ms(random() % 60);

	fbr_chunk_update(&file->body, chunk, FBR_CHUNK_READY);

	return NULL;
}

static void
_test_concurrent_gen(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	assert(chunk->id >= 1 && chunk->id <= _BODY_TEST_THREADS);
	size_t id = chunk->id - 1;

	fbr_test_logs("FETCH callback: %zu chunk: %lu", id, chunk->id);

	int calls = fbr_atomic_add(&_fetch_calls, 1);
	assert(calls <= _BODY_TEST_THREADS);

	chunk->state = FBR_CHUNK_LOADING;

	struct _thread_args *args = malloc(sizeof(*args));
	assert(args);
	args->fs = fs;
	args->fio = NULL;
	args->file = file;
	args->chunk = chunk;

	pt_assert(pthread_create(&_fetch_threads[id], NULL, _test_fetch_thread, args));
}

static void *
_test_fio_thread(void *arg)
{
	struct _thread_args *args = (struct _thread_args*)arg;
	struct fbr_fs *fs = args->fs;
	struct fbr_fio *fio = args->fio;

	fbr_fs_ok(fs);
	fbr_fio_ok(fio);

	fbr_fio_take(fio);

	int id = fbr_atomic_add(&_fio_thread_id, 1);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	fbr_test_logs("** fio_thread %d", id);

	fbr_sleep_ms(random() % 40);

	size_t offset = id * 1000;

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, offset, 2000);

	if (vector->chunks->length == 1) {
		assert(vector->chunks->list[0]->id == (size_t)id + 1)
		assert(vector->bufvec->count == 1);
	} else if (vector->chunks->length == 2) {
		assert(vector->chunks->list[0]->id == (size_t)id + 1)
		assert(vector->chunks->list[1]->id == (size_t)id + 2)
		assert(vector->bufvec->count == 2);
	} else {
		fbr_ABORT("bad chunk size %u", vector->chunks->length);
	}

	fbr_fio_vector_free(fs, fio, vector);
	fbr_fio_release(fs, fio);

	return NULL;
}

static const struct fbr_store_callbacks _TEST_CONCURRENT_CALLBACKS = {
	.fetch_chunk_f = _test_concurrent_gen
};

void
fbr_cmd_fs_test_body_concurrent_fio(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;

	fbr_fs_set_store(fs, &_TEST_CONCURRENT_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_fio *fio;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file_concurrent"));
	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		fbr_body_chunk_add(file, i + 1, i * 1000, 1000);
	}
	assert(_count_chunks(file) == _BODY_TEST_THREADS);
	assert(file->size == 1000 * _BODY_TEST_THREADS);

	fbr_inode_add(fs, file);
	fio = fbr_fio_alloc(fs, file);

	pthread_t threads[10];
	struct _thread_args args = {fs, fio, NULL, NULL};

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_create(&threads[i], NULL, _test_fio_thread, &args));
	}

	fbr_test_logs("# fio threads created");

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_fio_thread_id == _BODY_TEST_THREADS - 1);

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_join(_fetch_threads[i], NULL));
	}
	assert(_fetch_thread_id == _BODY_TEST_THREADS - 1);

	fbr_test_logs("# threads done");

	fbr_fio_release(fs, fio);

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs_test_body_concurrent_fio done");
}
