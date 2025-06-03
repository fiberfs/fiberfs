/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "fbr_test_store_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/store/test/fbr_dstore.h"

struct _write_args {
	struct fbr_fs *fs;
	struct fbr_file *file;
	struct fbr_fio *fio;
};

extern int _DEBUG_WBUFFER_ALLOC_SIZE;

#define _WBUFFER_SIZE		250
#define _FILE_SIZE		(10 * 1000)
#define _THREADS		10

static size_t _THREAD_COUNT;
static int _SHARED_FIO;
static size_t _ERROR_WBUFFER;
static size_t _ERROR_FLUSH;

static void
_init(void)
{
	assert_zero(_FILE_SIZE % _WBUFFER_SIZE);
	assert_zero(_FILE_SIZE % _THREADS);

	_THREAD_COUNT = 0;
	_SHARED_FIO = 0;
	_ERROR_WBUFFER = 0;
	_ERROR_FLUSH = 0;

	fbr_test_random_seed();
}

static unsigned char
_buffer_byte(size_t offset, size_t i)
{
	size_t pos = offset + i;
	unsigned char byte = (pos / 100);
	byte += (pos % 100);
	if (!byte) {
		byte = pos;
	}
	return byte;
}

static void
_buffer_check(size_t offset, unsigned char *buffer, size_t buffer_len)
{
	for (size_t i = 0; i < buffer_len; i++) {
		unsigned char byte = _buffer_byte(offset, i);
		fbr_test_ASSERT(buffer[i] == byte, "offset: %zu i: %zu found: %u expected: %u",
			offset, i, buffer[i], byte);
	}
}

static void
_buffer_init(size_t offset, unsigned char *buffer, size_t buffer_len)
{
	for (size_t i = 0; i < buffer_len; i++) {
		unsigned char byte = _buffer_byte(offset, i);
		buffer[i] = byte;
	}
}

static void
_write_wbuffer(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	if (_ERROR_WBUFFER && !(random() % 3)) {
		fbr_test_logs("*** ERROR WBUFFER offset: %zu id: %lu",
			wbuffer->offset, wbuffer->id);
		fbr_atomic_sub(&_ERROR_WBUFFER, 1);
		wbuffer->state = FBR_WBUFFER_ERROR;
		return;
	}

	fbr_dstore_wbuffer_write(fs, file, wbuffer);
}

static int
_write_index_root(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_writer *writer, struct fbr_directory *previous)
{
	if (_ERROR_FLUSH && !(random() % 2)) {
		fbr_test_logs("*** ERROR FLUSH");
		fbr_atomic_sub(&_ERROR_FLUSH, 1);
		return EBUSY;
	}

	return fbr_dstore_index_root_write(fs, directory, writer, previous);
}

static const struct fbr_store_callbacks _WRITE_CALLBACKS = {
	.chunk_read_f = fbr_dstore_chunk_read,
	.chunk_delete_f = fbr_dstore_chunk_delete,
	.wbuffer_write_f = _write_wbuffer,
	.directory_flush_f = fbr_directory_flush,
	.index_write_f = _write_index_root,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

static void *
_write_thread(void *arg)
{
	struct _write_args *args = arg;
	struct fbr_fs *fs = args->fs;
	struct fbr_file *file = args->file;
	struct fbr_fio *fio = args->fio;
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	int error_mode = 0;
	if (_ERROR_WBUFFER || _ERROR_FLUSH) {
		error_mode = 1;
	}

	fbr_test_index_request_start();

	size_t id = fbr_atomic_add(&_THREAD_COUNT, 1);
	size_t size = _FILE_SIZE / _THREADS;
	size_t offset = (id - 1) * size;

	fbr_test_logs(" ** Thread %zu running (%zu/%zu)", id, offset, size);

	while (_THREAD_COUNT < _THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_THREAD_COUNT == _THREADS);

	if (_SHARED_FIO) {
		assert(fio);
		fbr_fio_take(fio);
	} else {
		assert_zero(fio);
		fbr_inode_add(fs, file);
		fio = fbr_fio_alloc(fs, file);
	}

	char buffer[100];
	assert_zero(_FILE_SIZE % sizeof(buffer));
	memset(buffer, 0, sizeof(buffer));

	size_t pos = 0;
	int flushed = 0;

	while (pos < size) {
		_buffer_init(offset + pos, (unsigned char*)buffer, sizeof(buffer));
		fbr_wbuffer_write(fs, fio, offset + pos, buffer, sizeof(buffer));

		pos += sizeof(buffer);

		if (pos == size / 2 && !flushed) {
			flushed = 1;
			int ret = fbr_wbuffer_flush_fio(fs, fio);
			if (error_mode && ret) {
				fbr_test_logs("ERROR FLUSH thread %zu", id);
				pos -= sizeof(buffer);
			} else {
				assert_zero(ret);
			}
		}
	}
	assert(pos == size);

	fbr_sleep_ms(0.2);

	int ret;
	do {
		ret = fbr_wbuffer_flush_fio(fs, fio);
		if (error_mode && ret) {
			fbr_test_logs("ERROR FLUSH thread %zu", id);
		} else {
			assert_zero(ret);
		}
	} while (ret);

	fbr_fio_release(fs, fio);

	fbr_test_index_request_finish();

	fbr_test_logs(" ** Thread %zu done", id);

	return NULL;
}

static void
_write_test(void)
{
	struct fbr_test_context *test_ctx = fbr_test_get_ctx();

	fbr_dstore_init(test_ctx);

	struct fbr_fs *fs = fbr_test_fuse_mock(test_ctx);
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, &_WRITE_CALLBACKS);

	_DEBUG_WBUFFER_ALLOC_SIZE = _WBUFFER_SIZE;

	size_t __ERROR_WBUFFER = _ERROR_WBUFFER;
	size_t __ERROR_FLUSH = _ERROR_FLUSH;
	int error_mode = 0;
	if (_ERROR_WBUFFER || _ERROR_FLUSH) {
		error_mode = 1;
		_ERROR_WBUFFER = 0;
		_ERROR_FLUSH = 0;
	}

	fbr_test_logs("*** Allocating root directory");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, "file_write_store");
	struct fbr_file *file = fbr_file_alloc(fs, directory, &filename);
	file->state = FBR_FILE_OK;

	fbr_test_index_request_start();

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, directory, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs, &index_data);
	fbr_test_ERROR(ret, "fbr_index_write() failed");
	fbr_index_data_free(&index_data);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	fbr_dindex_release(fs, &directory);

	fbr_test_index_request_finish();

	fbr_test_logs("*** Initial fio");

	fbr_test_index_request_start();

	fbr_inode_add(fs, file);
	struct fbr_fio *fio = fbr_fio_alloc(fs, file);
	struct fbr_fio *shared_fio = NULL;
	if (_SHARED_FIO) {
		shared_fio = fio;
		fbr_fio_take(shared_fio);
	}

	char buffer[100];
	assert_zero(_FILE_SIZE % sizeof(buffer));
	memset(buffer, 0, sizeof(buffer));

	size_t offset = 0;
	while (offset < _FILE_SIZE) {
		fbr_wbuffer_write(fs, fio, offset, buffer, sizeof(buffer));
		if (offset % 1000 == 0) {
			ret = fbr_wbuffer_flush_fio(fs, fio);
			assert_zero(ret);
		}
		offset += sizeof(buffer);
	}
	assert(offset == _FILE_SIZE);
	assert(file->size == _FILE_SIZE);

	ret = fbr_wbuffer_flush_fio(fs, fio);
	assert_zero(ret);

	fbr_fio_release(fs, fio);
	fbr_test_index_request_finish();

	fbr_dstore_debug(0);
	assert(fs->stats.store_chunks > _FILE_SIZE / _WBUFFER_SIZE);

	fbr_test_logs("*** Starting write threads");

	_ERROR_WBUFFER = __ERROR_WBUFFER;
	_ERROR_FLUSH = __ERROR_FLUSH;

	assert_zero(_THREAD_COUNT);
	pthread_t threads[_THREADS];
	struct _write_args args = {fs, file, shared_fio};

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _write_thread, &args));
	}

	fbr_test_logs("*** Threads created");

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_THREAD_COUNT == _THREADS);
	assert(file->size == _FILE_SIZE);

	fbr_test_logs("*** Threads done");

	if (_SHARED_FIO) {
		assert(shared_fio);
		fbr_fio_release(fs, shared_fio);
	}

	fbr_test_logs("*** Load index");

	fbr_fs_release_all(fs, 0);

	directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	fbr_test_index_request_start();

	fbr_index_read(fs, directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(directory->file_count == 1);

	file = fbr_directory_find_file(directory, filename.name, filename.len);
	fbr_file_ok(file);

	fbr_test_logs("*** directory->generation: %lu", directory->generation);
	if (error_mode) {
		assert(directory->generation <= fs->stats.flushes + 1);
	} else {
		assert(directory->generation == fs->stats.flushes + 1);
	}

	fbr_test_index_request_finish();
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** Validation");

	fbr_test_index_request_start();

	fbr_inode_add(fs, file);
	fio = fbr_fio_alloc(fs, file);

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, 0, file->size);
	assert(vector);
	assert(vector->chunks);
	assert(vector->bufvec);

	struct fuse_bufvec *bufvec = vector->bufvec;
	size_t bufvec_len = 0;

	for (size_t i = 0; i < bufvec->count; i++) {
		struct fuse_buf *buf = &bufvec->buf[i];
		_buffer_check(bufvec_len, buf->mem, buf->size);
		bufvec_len += buf->size;
	}
	assert(bufvec_len == vector->size);
	assert(bufvec_len == _FILE_SIZE);

	fbr_fio_vector_free(fs, fio, vector);
	fbr_test_index_request_finish();
	fbr_fio_release(fs, fio);

	fbr_test_logs("*** Cleanup");

	fbr_fs_release_all(fs, 1);

	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);
	fbr_dstore_debug(0);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");
	if (_SHARED_FIO) {
		fbr_test_ASSERT(fs->stats.store_chunks >= _FILE_SIZE / _WBUFFER_SIZE,
			"mismatch %lu %d", fs->stats.store_chunks, _FILE_SIZE / _WBUFFER_SIZE);
	} else {
		fbr_test_ASSERT(fs->stats.store_chunks == _FILE_SIZE / _WBUFFER_SIZE,
			"mismatch %lu %d", fs->stats.store_chunks, _FILE_SIZE / _WBUFFER_SIZE);
	}

	if (error_mode) {
		fbr_test_logs("*** ERRORS wbuffer: %zu flush: %zu", __ERROR_WBUFFER,
			__ERROR_FLUSH);
	}

	fbr_request_pool_shutdown(fs);
	fbr_fs_free(fs);
}

void
fbr_cmd_store_write(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_init();

	_write_test();

	fbr_test_logs("store_write done");
}

void
fbr_cmd_store_write_shared(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_init();

	_SHARED_FIO = 1;

	_write_test();

	fbr_test_logs("store_write_shared done");
}

void
fbr_cmd_store_write_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_init();

	_ERROR_WBUFFER = 3;

	_write_test();

	fbr_test_logs("store_write_error done");
}

void
fbr_cmd_store_write_error_flush(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_init();

	_ERROR_FLUSH = 3;
	_SHARED_FIO = 1;

	_write_test();

	fbr_test_logs("store_write_error_flush done");
}
