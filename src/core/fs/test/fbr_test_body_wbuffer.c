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
#define _BODY_FILE_CHUNKS (_BODY_TEST_THREADS - 1)
#define _BODY_WRITE_SIZE 1000
#define _WBUFFER_ALLOC_SIZE 850;

static char _BUFFER[_BODY_WRITE_SIZE];

static pthread_t _STORE_THREADS[_BODY_TEST_THREADS];
static int _FIO_THREAD_ID;
static int _STORE_THREAD_ID;
static int _STORE_THREAD_COUNT;
static int _STORE_CALLS;
static int _STORE_ERROR_CHUNK_ID;
static int _STORE_ERRORS;
static int _SHARED_FIO;

extern int _DEBUG_WBUFFER_ALLOC_SIZE;

struct _thread_args {
	struct fbr_fs *fs;
	struct fbr_fio *fio;
	struct fbr_file *file;
	struct fbr_wbuffer *wbuffer;
	int id;
};

static void
_test_thread_init(void)
{
	_FIO_THREAD_ID = -1;
	_STORE_THREAD_ID = -1;
	_STORE_THREAD_COUNT = 0;
	_STORE_CALLS = 0;
	_STORE_ERROR_CHUNK_ID = -1;
	_STORE_ERRORS = 0;
	_SHARED_FIO = 0;

	_DEBUG_WBUFFER_ALLOC_SIZE = _WBUFFER_ALLOC_SIZE;

	fbr_test_random_seed();
}

static void *
_test_store_thread(void *arg)
{
	struct _thread_args *args = (struct _thread_args*)arg;
	struct fbr_fs *fs = args->fs;
	struct fbr_file *file = args->file;
	struct fbr_wbuffer *wbuffer = args->wbuffer;
	int id = args->id;

	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_SYNC);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	int count = fbr_atomic_add(&_STORE_THREAD_COUNT, 1);
	assert(count > 0);
	assert(count <= _BODY_TEST_THREADS);

	free(args);

	fbr_test_logs("STORE thread %d wbuffer: %lu", id, wbuffer->offset);

	while (_STORE_THREAD_COUNT < _BODY_TEST_THREADS) {
		fbr_sleep_ms(0.1);
	}

	fbr_test_logs("STORE synced: %d", id);

	fbr_sleep_ms(random() % 60);

	if (id == _STORE_ERROR_CHUNK_ID) {
		fbr_test_logs("STORE ERROR: %d", id);
		fbr_wbuffer_update(wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_wbuffer_update(wbuffer, FBR_WBUFFER_DONE);
	}

	return NULL;
}

static int
_test_concurrent_store(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	int id = fbr_atomic_add(&_STORE_THREAD_ID, 1);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	fbr_test_logs("STORE %d wbuffer offset: %lu", id, wbuffer->offset);

	int calls = fbr_atomic_add(&_STORE_CALLS, 1);
	assert(calls <= _BODY_TEST_THREADS);

	wbuffer->state = FBR_WBUFFER_SYNC;

	struct _thread_args *args = malloc(sizeof(*args));
	assert(args);
	args->fs = fs;
	args->fio = NULL;
	args->file = file;
	args->wbuffer = wbuffer;
	args->id = id;

	pt_assert(pthread_create(&_STORE_THREADS[id], NULL, _test_store_thread, args));

	return 0;
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

	size_t offset = id * sizeof(_BUFFER);

	size_t written = fbr_wbuffer_write(fs, fio, offset, _BUFFER, sizeof(_BUFFER));
	assert_dev(written == sizeof(_BUFFER));

	if (!_SHARED_FIO) {
		int ret = fbr_wbuffer_flush(fs, fio);
		assert_zero(ret);
	}

	fbr_fio_release(fs, fio);

	return NULL;
}

static int
_test_flush_wbuffers(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffers);

	return 0;
}

static const struct fbr_store_callbacks _TEST_WBUFFER_CALLBACKS = {
	.store_wbuffer_f = _test_concurrent_store,
	.flush_wbuffers_f = _test_flush_wbuffers
};

static void
_test_concurrent_fio(void)
{
	assert(_FIO_THREAD_ID == -1);

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;

	fbr_fs_set_store(fs, &_TEST_WBUFFER_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_fio *fio = NULL;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file_concurrent"));
	for (size_t i = 0; i < _BODY_FILE_CHUNKS; i++) {
		fbr_body_chunk_add(file, i + 1, i * 1000, 1000);
	}
	assert(fbr_fs_test_count_chunks(file) == _BODY_FILE_CHUNKS);
	assert(file->size == 1000 * _BODY_FILE_CHUNKS);

	if (_SHARED_FIO) {
		fbr_inode_add(fs, file);
		fio = fbr_fio_alloc(fs, file);
	}

	pthread_t threads[10];
	struct _thread_args args = {fs, fio, file, NULL, 0};

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_create(&threads[i], NULL, _test_fio_thread, &args));
	}

	fbr_test_logs("# fio threads created");

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_FIO_THREAD_ID == _BODY_TEST_THREADS - 1);

	if (_SHARED_FIO) {
		int ret = fbr_wbuffer_flush(fs, fio);
		assert_zero(ret);
	}

	for (size_t i = 0; i < _BODY_TEST_THREADS; i++) {
		pt_assert(pthread_join(_STORE_THREADS[i], NULL));
	}
	assert(_STORE_THREAD_ID == _BODY_TEST_THREADS - 1);

	fbr_test_logs("# threads done");

	assert(_STORE_CALLS == _BODY_TEST_THREADS);

	if (_STORE_ERROR_CHUNK_ID >= 0) {
		assert(_STORE_ERRORS);
	}

	if (_SHARED_FIO) {
		fbr_fio_release(fs, fio);
	}

	assert(file->size == _BODY_TEST_THREADS * sizeof(_BUFFER));

	struct fbr_chunk_list *removed = NULL;
	struct fbr_chunk_list *chunks = fbr_chunk_list_file(file, 0, file->size, &removed);

	fbr_chunk_list_debug(fs, chunks, "FILE");
	assert(chunks->length == _BODY_TEST_THREADS);
	for (size_t i = 0; i < chunks->length; i++) {
		assert(chunks->list[i]->id > _BODY_TEST_THREADS);
	}

	fbr_chunk_list_debug(fs, removed, "REMOVED");
	assert(removed->length == _BODY_FILE_CHUNKS);
	for (size_t i = 0; i < removed->length; i++) {
		assert(removed->list[i]->id == i + 1);
	}

	fbr_chunk_list_free(chunks);
	fbr_chunk_list_free(removed);

	fbr_fs_free(fs);

	fbr_test_logs("fs_test_body_pwbuffer done");
}

void
fbr_cmd_fs_test_body_pwbuffer(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_test_concurrent_fio();
}

void
fbr_cmd_fs_test_body_spwbuffer(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_SHARED_FIO = 1;

	_test_concurrent_fio();
}

void
fbr_cmd_fs_test_body_pwbuffer_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_STORE_ERROR_CHUNK_ID = (random() % _BODY_TEST_THREADS) + 1;
	assert(_STORE_ERROR_CHUNK_ID);

	_SHARED_FIO = 1;

	fbr_test_logs("fs_test_body_pwbuffer_error: %d", _STORE_ERROR_CHUNK_ID);

	_test_concurrent_fio();
}
