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

#define _BODY_TEST_THREADS 10

static pthread_t _FETCH_THREADS[_BODY_TEST_THREADS];
static int _FIO_THREAD_ID;
static int _FETCH_THREAD_ID;
static int _FETCH_CALLS;
static fbr_id_t _FETCH_ERROR_CHUNK_ID;
static int _FETCH_ERRORS;
static int _SHARED_FIO;

struct _thread_args {
	struct fbr_fs *fs;
	struct fbr_fio *fio;
	struct fbr_file *file;
	struct fbr_chunk *chunk;
};

static void
_test_thread_init(void)
{
	_FIO_THREAD_ID = -1;
	_FETCH_THREAD_ID = -1;
	_FETCH_CALLS = 0;
	_FETCH_ERROR_CHUNK_ID = 0;
	_FETCH_ERRORS = 0;
	_SHARED_FIO = 0;

	fbr_test_random_seed();
}

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

	int id = fbr_atomic_add(&_FETCH_THREAD_ID, 1);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	fbr_test_logs("FETCH thread: %d chunk: %lu", id, chunk->id);

	fbr_chunk_update(fs, &file->body, chunk, FBR_CHUNK_LOADING);

	while (_FETCH_THREAD_ID < _BODY_TEST_THREADS - 1) {
		fbr_sleep_ms(0.1);
	}

	fbr_test_logs("FETCH synced: %d", id);

	fbr_sleep_ms(random() % 60);

	if (chunk->id == _FETCH_ERROR_CHUNK_ID) {
		fbr_test_logs("FETCH ERROR: %lu", chunk->id);
		chunk->data = NULL;
		fbr_chunk_update(fs, &file->body, chunk, FBR_CHUNK_EMPTY);
	} else {
		fbr_chunk_update(fs, &file->body, chunk, FBR_CHUNK_READY);
	}

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

	fbr_test_logs("FETCH chunk: %lu", chunk->id);

	int calls = fbr_atomic_add(&_FETCH_CALLS, 1);

	// Chunk was released too early...
	if (calls > _BODY_TEST_THREADS) {
		fbr_test_logs("FETCH regen chunk: %lu", chunk->id);
		if (chunk->id == _FETCH_ERROR_CHUNK_ID) {
			fbr_test_logs("FETCH regen chunk ERROR: %lu", chunk->id);
			chunk->state = FBR_CHUNK_EMPTY;
		} else {
			chunk->data = (void*)chunk->id;
			chunk->state = FBR_CHUNK_READY;
		}
		return;
	}

	chunk->state = FBR_CHUNK_LOADING;

	struct _thread_args *args = malloc(sizeof(*args));
	assert(args);
	args->fs = fs;
	args->fio = NULL;
	args->file = file;
	args->chunk = chunk;

	pt_assert(pthread_create(&_FETCH_THREADS[id], NULL, _test_fetch_thread, args));
}

static void *
_test_fio_thread(void *arg)
{
	struct _thread_args *args = (struct _thread_args*)arg;
	struct fbr_fs *fs = args->fs;
	struct fbr_file *file = args->file;
	struct fbr_fio *fio = args->fio;

	fbr_fs_ok(fs);
	fbr_file_ok(file);

	if (!_SHARED_FIO) {
		assert_zero(fio);
		fbr_inode_add(fs, file);
		fio = fbr_fio_alloc(fs, file);
		fbr_fio_ok(fio);
	} else {
		fbr_fio_ok(fio);
		fbr_fio_take(fio);
	}

	int id = fbr_atomic_add(&_FIO_THREAD_ID, 1);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	fbr_test_logs("** fio_thread %d", id);

	fbr_sleep_ms(random() % 40);

	size_t offset = id * 1000;

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, offset, 2000);

	if (_FETCH_ERROR_CHUNK_ID && !vector) {
		fbr_atomic_add(&_FETCH_ERRORS, 1);
		fbr_test_logs("** fio_thread %d got vector ERROR", id);
	} else {
		assert(vector);
		assert(vector->chunks);
		assert(vector->bufvec);

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
	}

	fbr_fio_release(fs, fio);

	return NULL;
}

static const struct fbr_store_callbacks _TEST_CONCURRENT_CALLBACKS = {
	.fetch_chunk_f = _test_concurrent_gen
};

static void
_test_concurrent_fio(void)
{
	assert(_FIO_THREAD_ID == -1);

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;

	fbr_fs_set_store(fs, &_TEST_CONCURRENT_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_fio *fio = NULL;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file_concurrent"));
	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		fbr_body_chunk_add(file, i + 1, i * 1000, 1000);
	}
	assert(fbr_fs_test_count_chunks(file) == _BODY_TEST_THREADS);
	assert(file->size == 1000 * _BODY_TEST_THREADS);

	if (_SHARED_FIO) {
		fbr_inode_add(fs, file);
		fio = fbr_fio_alloc(fs, file);
	}

	pthread_t threads[10];
	struct _thread_args args = {fs, fio, file, NULL};

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_create(&threads[i], NULL, _test_fio_thread, &args));
	}

	fbr_test_logs("# fio threads created");

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_FIO_THREAD_ID == _BODY_TEST_THREADS - 1);

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_join(_FETCH_THREADS[i], NULL));
	}
	assert(_FETCH_THREAD_ID == _BODY_TEST_THREADS - 1);

	fbr_test_logs("# threads done");

	assert(_FETCH_CALLS >= _BODY_TEST_THREADS);

	if (_FETCH_ERROR_CHUNK_ID) {
		assert(_FETCH_ERRORS);
	}

	if (_SHARED_FIO) {
		fbr_fio_release(fs, fio);
	}

	fbr_fs_free(fs);

	fbr_test_logs("fs_test_body_pfio done");
}

void
fbr_cmd_fs_test_body_pfio(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_test_concurrent_fio();
}

void
fbr_cmd_fs_test_body_spfio(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_SHARED_FIO = 1;

	_test_concurrent_fio();
}

void
fbr_cmd_fs_test_body_spfio_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_FETCH_ERROR_CHUNK_ID = (random() % _BODY_TEST_THREADS) + 1;
	assert(_FETCH_ERROR_CHUNK_ID);

	_SHARED_FIO = 1;

	fbr_test_logs("fs_test_body_pfio_error: %lu", _FETCH_ERROR_CHUNK_ID);

	_test_concurrent_fio();
}
