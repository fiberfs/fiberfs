/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"

#define _BODY_TEST_THREADS 10
#define _BODY_WRITE_SIZE 1000

static pthread_t _STORE_THREADS[_BODY_TEST_THREADS * 3];
static pthread_t _FETCH_THREADS[_BODY_TEST_THREADS];
static int _FIO_THREAD_ID;
static int _FIO_READ_THREAD_ID;
static volatile int _TEST_OVER;
static int _STORE_THREAD_ID;
static int _FETCH_THREAD_ID;
static volatile size_t _STORE_CALLS;
static volatile size_t _FETCH_CALLS;
static int _STORE_ERROR_THREAD_ID;
static int _SHARED_FIO;
static size_t _BODY_CHUNKS;
static size_t _WBUFFER_ALLOC_SIZE;

extern int _DEBUG_WBUFFER_ALLOC_SIZE;

struct _thread_args {
	struct fbr_fs *fs;
	struct fbr_fio *fio;
	struct fbr_file *file;
	struct fbr_wbuffer *wbuffer;
	struct fbr_chunk *chunk;
	int id;
};

static void
_test_thread_init(void)
{
	fbr_test_random_seed();

	_FIO_THREAD_ID = -1;
	_FIO_READ_THREAD_ID = -1;
	_TEST_OVER = 0;
	_STORE_THREAD_ID = -1;
	_FETCH_THREAD_ID = -1;
	_STORE_CALLS = 0;
	_FETCH_CALLS = 0;
	_STORE_ERROR_THREAD_ID = -1;
	_SHARED_FIO = 0;
	_BODY_CHUNKS = (random() % _BODY_TEST_THREADS) + 1;
	_WBUFFER_ALLOC_SIZE = (random() % (_BODY_WRITE_SIZE * 2)) + 1;

	_DEBUG_WBUFFER_ALLOC_SIZE = _WBUFFER_ALLOC_SIZE;
}

static void
_fill_buffer(size_t offset, unsigned char *buffer, size_t buffer_len)
{
	for (size_t i = 0; i < buffer_len; i++) {
		buffer[i] = (offset + i) % UCHAR_MAX;
	}
}

static void
_check_buffer(size_t offset, unsigned char *buffer, size_t buffer_len, int zero_ok)
{
	for (size_t i = 0; i < buffer_len; i++) {
		if (zero_ok && !buffer[i]) {
			continue;
		}
		unsigned char value = (offset + i) % UCHAR_MAX;
		assert(buffer[i] == value);
	}
}

static void *
_test_fetch_thread(void *arg)
{
	struct _thread_args *args = (struct _thread_args*)arg;
	struct fbr_fs *fs = args->fs;
	struct fbr_file *file = args->file;
	struct fbr_chunk *chunk = args->chunk;
	int id = args->id;

	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_LOADING);

	free(args);

	fbr_test_logs("FETCH thread: %d chunk: %zu (%lu)", id, chunk->offset, chunk->id);

	fbr_chunk_update(fs, &file->body, chunk, FBR_CHUNK_LOADING);

	fbr_sleep_ms(random() % 5);

	chunk->data = malloc(chunk->length);
	assert(chunk->data);
	_fill_buffer(chunk->offset, chunk->data, chunk->length);

	chunk->do_free = 1;

	fbr_chunk_update(fs, &file->body, chunk, FBR_CHUNK_READY);

	return NULL;
}

static void
_test_concurrent_gen_wbuffer(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	int id = fbr_atomic_add(&_FETCH_THREAD_ID, 1);
	assert(id >= 0);

	fbr_test_logs("FETCH chunk: %zu (%lu)", chunk->offset, chunk->id);

	if ((size_t)id >= fbr_array_len(_FETCH_THREADS) || _TEST_OVER) {
		fbr_test_logs("FETCH regen chunk: %zu (%lu)", chunk->offset, chunk->id);

		chunk->data = malloc(chunk->length);
		assert(chunk->data);
		_fill_buffer(chunk->offset, chunk->data, chunk->length);

		chunk->do_free = 1;
		chunk->state = FBR_CHUNK_READY;

		return;
	}

	size_t calls = fbr_atomic_add(&_FETCH_CALLS, 1);
	assert(calls <= fbr_array_len(_FETCH_THREADS));

	chunk->state = FBR_CHUNK_LOADING;

	struct _thread_args *args = malloc(sizeof(*args));
	assert(args);
	args->fs = fs;
	args->fio = NULL;
	args->file = file;
	args->wbuffer = NULL;
	args->chunk = chunk;
	args->id = id;

	pt_assert(pthread_create(&_FETCH_THREADS[id], NULL, _test_fetch_thread, args));
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
	assert((size_t)id < fbr_array_len(_STORE_THREADS));

	free(args);

	fbr_sleep_ms(random() % 60 + 10);

	fbr_test_logs("STORE thread %d wbuffer: %lu", id, wbuffer->offset);

	if (id == _STORE_ERROR_THREAD_ID) {
		fbr_test_logs("STORE ERROR: %d", id);
		fbr_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
	} else {
		fbr_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
	}

	return NULL;
}

static void
_test_concurrent_store(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	int id = fbr_atomic_add(&_STORE_THREAD_ID, 1);
	assert(id >= 0);

	if ((size_t)id >= fbr_array_len(_STORE_THREADS)) {
		fbr_test_logs("STORE %d wbuffer offset: %lu DONE", id, wbuffer->offset);
		wbuffer->state = FBR_WBUFFER_DONE;
		return;
	}

	fbr_test_logs("STORE %d wbuffer offset: %lu", id, wbuffer->offset);

	size_t calls = fbr_atomic_add(&_STORE_CALLS, 1);
	assert(calls <= fbr_array_len(_STORE_THREADS));

	wbuffer->state = FBR_WBUFFER_SYNC;

	struct _thread_args *args = malloc(sizeof(*args));
	assert(args);
	args->fs = fs;
	args->fio = NULL;
	args->file = file;
	args->wbuffer = wbuffer;
	args->chunk = NULL;
	args->id = id;

	pt_assert(pthread_create(&_STORE_THREADS[id], NULL, _test_store_thread, args));
}

static int
_test_flush_wbuffers(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    enum fbr_index_flags flags)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffers);
	assert_zero(flags);

	struct fbr_wbuffer *wbuffer = wbuffers;
	size_t errors = 0;

	while (wbuffer) {
		fbr_wbuffer_ok(wbuffer);
		if (_STORE_ERROR_THREAD_ID >= 0) {
			assert(wbuffer->state == FBR_WBUFFER_WRITING ||
				wbuffer->state == FBR_WBUFFER_DONE);
		} else {
			assert(wbuffer->state == FBR_WBUFFER_DONE);
		}

		if (wbuffer->state == FBR_WBUFFER_WRITING) {
			errors++;
		}

		wbuffer = wbuffer->next;
	}

	if (_STORE_ERROR_THREAD_ID >= 0) {
		assert(errors);
	} else {
		assert_zero(errors);
	}

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

	char buffer[_BODY_WRITE_SIZE];
	size_t offset = id * sizeof(buffer);

	_fill_buffer(offset, (unsigned char*)buffer, sizeof(buffer));

	size_t total = 0;

	while (total < sizeof(buffer)) {
		size_t remaining = sizeof(buffer) - total;
		size_t wsize = (random() % sizeof(buffer)) + 1;
		if (wsize > remaining) {
			wsize = remaining;
		}

		fbr_test_logs("** fio_thread %d write offset: %zu (%zu) size: %zu",
			id, offset, offset + total, wsize);

		assert(total + wsize <= sizeof(buffer));
		fbr_wbuffer_write(fs, fio, offset + total, buffer + total, wsize);

		total += wsize;
	}
	assert(total == sizeof(buffer));

	if (!_SHARED_FIO) {
		int ret = fbr_wbuffer_flush_fio(fs, fio);
		if (_STORE_ERROR_THREAD_ID >= 0) {
			assert(ret);
			_test_flush_wbuffers(fs, file, fio->wbuffers, 0);
			fbr_wbuffers_free(fio->wbuffers);
			fio->wbuffers = NULL;
		} else {
			assert_zero(ret);
		}
	}

	fbr_fio_release(fs, fio);

	return NULL;
}

static void *
_test_fio_read_thread(void *arg)
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

	int id = fbr_atomic_add(&_FIO_READ_THREAD_ID, 1);
	assert(id >= 0);
	assert(id < _BODY_TEST_THREADS);

	fbr_test_logs("** fio_read_thread %d", id);

	size_t count = 0;

	while (!_TEST_OVER && count < 3) {
		size_t file_size = file->size;
		assert(file_size);
		size_t offset = random() % file_size;
		size_t length = (random() % file_size) + 1;

		fbr_test_logs("** fio_read_thread %d vector: %zu/%zu", id, offset, length);

		struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, offset, length);
		assert(vector);
		assert(vector->chunks);
		assert(vector->bufvec);

		struct fuse_bufvec *bufvec = vector->bufvec;
		size_t bufvec_len = 0;

		for (size_t i = 0; i < bufvec->count; i++) {
			struct fuse_buf *buf = &bufvec->buf[i];
			_check_buffer(offset + bufvec_len, buf->mem, buf->size, 1);
			bufvec_len += buf->size;
		}
		assert(offset == vector->offset);
		assert(bufvec_len == vector->size);

		fbr_fio_vector_free(fs, fio, vector);

		count++;
	}

	fbr_fio_release(fs, fio);

	return NULL;
}

static const struct fbr_store_callbacks _TEST_WBUFFER_CALLBACKS = {
	.chunk_read_f = _test_concurrent_gen_wbuffer,
	.wbuffer_write_f = _test_concurrent_store,
	.wbuffers_flush_f = _test_flush_wbuffers
};

static void
_test_concurrent_fio(void)
{
	assert(_FIO_THREAD_ID == -1);

	struct fbr_fs *fs = fbr_test_fs_alloc();

	fbr_fs_set_store(fs, &_TEST_WBUFFER_CALLBACKS);

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	struct fbr_file *file;
	struct fbr_path_name name;
	struct fbr_fio *fio = NULL;

	file = fbr_file_alloc(fs, root, fbr_path_name_init(&name, "file_concurrent"));
	for (size_t i = 0; i < _BODY_CHUNKS; i++) {
		fbr_body_chunk_add(fs, file, i + 1, i * 1000, 1000);
	}
	file->state = FBR_FILE_OK;
	assert(fbr_test_fs_count_chunks(file) == _BODY_CHUNKS);
	assert(file->size == 1000 * _BODY_CHUNKS);

	if (_SHARED_FIO) {
		fbr_inode_add(fs, file);
		fio = fbr_fio_alloc(fs, file);
	}

	pthread_t threads[_BODY_TEST_THREADS];
	pthread_t read_threads[_BODY_TEST_THREADS];
	struct _thread_args args = {fs, fio, file, NULL, NULL, 0};

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _test_fio_thread, &args));
	}
	for (size_t i = 0; i < fbr_array_len(read_threads); i++) {
		pt_assert(pthread_create(&read_threads[i], NULL, _test_fio_read_thread, &args));
	}

	fbr_test_logs("# fio threads created");

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_FIO_THREAD_ID == _BODY_TEST_THREADS - 1);

	_TEST_OVER = 1;

	for (size_t i = 0; i < fbr_array_len(read_threads); i++) {
		pt_assert(pthread_join(read_threads[i], NULL));
	}
	assert(_FIO_READ_THREAD_ID == _BODY_TEST_THREADS - 1);

	if (_SHARED_FIO) {
		int ret = fbr_wbuffer_flush_fio(fs, fio);
		if (_STORE_ERROR_THREAD_ID >= 0) {
			assert(ret);
			_test_flush_wbuffers(fs, file, fio->wbuffers, 0);
			fbr_wbuffers_free(fio->wbuffers);
			fio->wbuffers = NULL;
		} else {
			assert_zero(ret);
		}
	}

	for (size_t i = 0; i < _STORE_CALLS; i++) {
		pt_assert(pthread_join(_STORE_THREADS[i], NULL));
	}
	assert(_STORE_THREAD_ID >= 0);
	assert(_STORE_CALLS);

	for (size_t i = 0; i < _FETCH_CALLS; i++) {
		pt_assert(pthread_join(_FETCH_THREADS[i], NULL));
	}

	fbr_test_logs("# threads done");

	if (_SHARED_FIO) {
		fbr_fio_release(fs, fio);
	}

	assert(file->size == _BODY_TEST_THREADS * _BODY_WRITE_SIZE);

	struct fbr_chunk_list *removed = NULL;
	struct fbr_chunk_list *chunks = fbr_body_chunk_range(file, 0, file->size, &removed, NULL);

	fbr_chunk_list_debug(fs, chunks, "FILE");
	assert(chunks->length);
	for (size_t i = 0; i < chunks->length; i++) {
		assert(chunks->list[i]->id > _BODY_TEST_THREADS);
	}

	fbr_chunk_list_debug(fs, removed, "REMOVED");
	assert(removed->length == _BODY_CHUNKS);
	for (size_t i = 0; i < removed->length; i++) {
		assert(removed->list[i]->id == i + 1);
	}

	fbr_chunk_list_free(chunks);
	fbr_chunk_list_free(removed);

	fbr_test_logs("# final vector validation");

	fbr_inode_add(fs, file);
	fio = fbr_fio_alloc(fs, file);

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, 0, file->size);
	fbr_chunk_vector_ok(vector);

	chunks = vector->chunks;
	fbr_chunk_list_ok(chunks);
	assert(chunks->length);
	for (size_t i = 0; i < chunks->length; i++) {
		assert(chunks->list[i]->id > _BODY_TEST_THREADS);
	}

	struct fuse_bufvec *bufvec = vector->bufvec;
	size_t bufvec_len = 0;
	assert(bufvec);

	for (size_t i = 0; i < bufvec->count; i++) {
		struct fuse_buf *buf = &bufvec->buf[i];
		_check_buffer(bufvec_len, buf->mem, buf->size, 0);
		bufvec_len += buf->size;
	}
	assert_zero(vector->offset);
	assert(bufvec_len == vector->size);

	fbr_fio_vector_free(fs, fio, vector);

	fbr_fio_release(fs, fio);

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
fbr_cmd_fs_test_body_spwbuffer_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_thread_init();

	_STORE_ERROR_THREAD_ID = 0;
	_SHARED_FIO = 1;

	fbr_test_logs("fs_test_body_pwbuffer_error: %d", _STORE_ERROR_THREAD_ID);

	_test_concurrent_fio();
}
