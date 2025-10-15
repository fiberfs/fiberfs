/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "core/request/fbr_request.h"

static void *_cstore_async_loop(void *arg);
static void _cstore_async_op(struct fbr_cstore *cstore, struct fbr_cstore_op *op);

void
fbr_cstore_async_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_async *async = &cstore->async;

	fbr_zero(async);
	pt_assert(pthread_mutex_init(&async->queue_lock, NULL));
	pt_assert(pthread_cond_init(&async->todo_ready, NULL));

	async->callback = _cstore_async_op;

	TAILQ_INIT(&async->todo_list);
	TAILQ_INIT(&async->active_list);
	TAILQ_INIT(&async->free_list);

	fbr_cstore_worker_key_init();

	for (size_t i = 0; i < fbr_array_len(async->ops); i++) {
		struct fbr_cstore_op *op = &async->ops[i];

		op->magic = FBR_CSTORE_OP_MAGIC;
		op->type = FBR_CSOP_NONE;

		TAILQ_INSERT_TAIL(&async->free_list, op, entry);

		fbr_cstore_op_ok(op);
	}

	async->threads_max = _CSTORE_CONFIG.async_threads;

	for (size_t i = 0; i < async->threads_max; i++) {
		pt_assert(pthread_create(&async->threads[i], NULL, _cstore_async_loop, cstore));
	}

	while (async->threads_running != async->threads_max) {
		fbr_sleep_ms(0.1);
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_ASYNC, FBR_REQID_CSTORE, "threads running: %zu",
		async->threads_running);
}

int
fbr_cstore_async_queue(struct fbr_cstore *cstore, enum fbr_cstore_op_type type, void *param0,
    void *param1, void *param2, void *param3, void *param4, fbr_cstore_async_done_f done_cb,
    void *done_arg)
{
	fbr_cstore_ok(cstore);
	assert(type > FBR_CSOP_NONE && type < __FBR_CSOP_END);

	struct fbr_cstore_async *async = &cstore->async;
	pt_assert(pthread_mutex_lock(&async->queue_lock));

	// TODO how do we want to exit?
	assert_zero(async->exit);

	if (TAILQ_EMPTY(&async->free_list) || async->queue_len >= async->threads_max) {
		pt_assert(pthread_mutex_unlock(&async->queue_lock));
		return 1;
	}

	fbr_rlog(FBR_LOG_CS_ASYNC, "queue request: %s", fbr_cstore_async_type(type));

	struct fbr_cstore_op *op = TAILQ_FIRST(&async->free_list);
	fbr_cstore_op_ok(op);
	assert_dev(op->type == FBR_CSOP_NONE);

	TAILQ_REMOVE(&async->free_list, op, entry);

	fbr_zero(op);
	op->magic = FBR_CSTORE_OP_MAGIC;
	op->type = type;
	op->param0 = param0;
	op->param1 = param1;
	op->param2 = param2;
	op->param3 = param3;
	op->param4 = param4;
	op->done_cb = done_cb;
	op->done_arg = done_arg;

	struct fbr_request *request = fbr_request_get();
	if (request) {
		op->request_id = request->id;
	} else {
		struct fbr_cstore_worker *worker = fbr_cstore_worker_get();
		if (worker) {
			op->request_id = worker->request_id;
		}
	}

	TAILQ_INSERT_TAIL(&async->todo_list, op, entry);

	async->queue_len++;
	assert(async->queue_len <= FBR_CSTORE_ASYNC_THREAD_MAX);

	pt_assert(pthread_cond_signal(&async->todo_ready));

	pt_assert(pthread_mutex_unlock(&async->queue_lock));

	return 0;
}

static void
_cstore_async_op(struct fbr_cstore *cstore, struct fbr_cstore_op *op)
{
	assert_dev(cstore);
	assert_dev(op);

	switch (op->type) {
		case FBR_CSOP_TEST:
			return;
		case FBR_CSOP_WBUFFER_WRITE:
			fbr_cstore_io_wbuffer_write(op->param0, op->param1, op->param2);
			return;
		case FBR_CSOP_WBUFFER_SEND:
			fbr_cstore_s3_wbuffer_send(op->param0, op->param1, op->param2, op->param3);
			return;
		case FBR_CSOP_CHUNK_READ:
			fbr_cstore_io_chunk_read(op->param0, op->param1, op->param2);
			return;
		case FBR_CSOP_URL_DELETE:
			fbr_cstore_io_delete_url(op->param0, op->param1, (size_t)op->param2,
				(fbr_id_t)op->param3, (intptr_t)op->param4);
			return;
		case FBR_CSOP_INDEX_SEND:
			fbr_cstore_s3_index_send(op->param0, op->param1, op->param2, op->param3,
				(fbr_id_t)op->param4);
			return;
		case FBR_CSOP_NONE:
		case __FBR_CSOP_END:
			break;

	}

	fbr_ABORT("bad async op: %d", op->type);
}

static void *
_cstore_async_loop(void *arg)
{
	assert(arg);

	struct fbr_cstore *cstore = arg;
	fbr_cstore_ok(cstore);
	struct fbr_cstore_async *async = &cstore->async;

	struct fbr_cstore_worker *worker = fbr_cstore_worker_alloc(cstore);
	fbr_cstore_worker_ok(worker);

	pt_assert(pthread_mutex_lock(&async->queue_lock));

	async->threads_running++;
	worker->thread_id = fbr_request_id_thread_gen();
	worker->thread_pos = async->threads_running;

	fbr_thread_name("fbr_async");

	while (!async->exit) {
		if (worker->thread_pos > async->threads_max) {
			break;
		}

		if (TAILQ_EMPTY(&async->todo_list)) {
			pt_assert(pthread_cond_wait(&async->todo_ready, &async->queue_lock));
			continue;
		}

		struct fbr_cstore_op *op = TAILQ_FIRST(&async->todo_list);
		fbr_cstore_op_ok(op);

		TAILQ_REMOVE(&async->todo_list, op, entry);
		TAILQ_INSERT_TAIL(&async->active_list, op, entry);

		pt_assert(pthread_mutex_unlock(&async->queue_lock));

		fbr_cstore_worker_init(worker);

		fbr_rlog(FBR_LOG_CS_ASYNC, "calling op: %s (request_id: %lu)",
			fbr_cstore_async_type(op->type), op->request_id);

		assert(async->callback);
		async->callback(cstore, op);

		if (op->done_cb) {
			op->done_cb(op);
		}

		fbr_cstore_worker_finish(worker);

		pt_assert(pthread_mutex_lock(&async->queue_lock));

		op->type = FBR_CSOP_NONE;

		TAILQ_REMOVE(&async->active_list, op, entry);
		TAILQ_INSERT_TAIL(&async->free_list, op, entry);

		async->queue_len--;
		assert(async->queue_len <= FBR_CSTORE_ASYNC_THREAD_MAX);
	}

	async->threads_running--;

	pt_assert(pthread_mutex_unlock(&async->queue_lock));

	fbr_cstore_worker_free(worker);

	return NULL;
}

void
fbr_cstore_async_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_async *async = &cstore->async;

	pt_assert(pthread_mutex_lock(&async->queue_lock));
	async->exit = 1;
	pt_assert(pthread_cond_broadcast(&async->todo_ready));
	pt_assert(pthread_mutex_unlock(&async->queue_lock));

	for (size_t i = 0; i < async->threads_max; i++) {
		pt_assert(pthread_join(async->threads[i], NULL));
	}

	assert_zero(async->threads_running);
	assert_zero(async->queue_len);
	assert(TAILQ_EMPTY(&async->todo_list));
	assert(TAILQ_EMPTY(&async->active_list));

	pt_assert(pthread_mutex_destroy(&async->queue_lock));
	pt_assert(pthread_cond_destroy(&async->todo_ready));

	fbr_cstore_worker_key_free();

	fbr_zero(async);
}

void
fbr_cstore_async_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
    struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		wbuffer->state = FBR_WBUFFER_ERROR;
		return;
	}

	wbuffer->state = FBR_WBUFFER_SYNC;

	int ret = fbr_cstore_async_queue(cstore, FBR_CSOP_WBUFFER_WRITE, fs, file, wbuffer, NULL,
		NULL, NULL, NULL);
	if (ret) {
		wbuffer->state = FBR_WBUFFER_READY;
		fbr_cstore_io_wbuffer_write(fs, file, wbuffer);
		return;
	}
}

void
fbr_cstore_async_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return;
	}

	chunk->state = FBR_CHUNK_LOADING;

	int ret = fbr_cstore_async_queue(cstore, FBR_CSOP_CHUNK_READ, fs, file, chunk, NULL, NULL,
		NULL, NULL);
	if (ret) {
		chunk->state = FBR_CHUNK_EMPTY;
		fbr_cstore_io_chunk_read(fs, file, chunk);
		return;
	}
}

static void
_async_chunk_url_done(struct fbr_cstore_op *op)
{
	fbr_cstore_op_ok(op);
	assert(op->type == FBR_CSOP_URL_DELETE);

	free(op->param1);
	op->param1 = NULL;
}

static void
_async_url_delete(struct fbr_cstore *cstore, const char *url, size_t url_len, fbr_id_t id,
    enum fbr_cstore_entry_type type)
{
	assert_dev(cstore);
	assert_dev(url);
	assert_dev(url_len);

	size_t buffer_len = url_len + 1;
	char *buffer = malloc(buffer_len);
	fbr_strcpy(buffer, buffer_len, url);

	static_ASSERT(sizeof(void*) >= sizeof(url_len));
	static_ASSERT(sizeof(void*) >= sizeof(id));
	static_ASSERT(sizeof(void*) >= sizeof(type));

	int ret = fbr_cstore_async_queue(cstore, FBR_CSOP_URL_DELETE, cstore, buffer, (void*)url_len,
		(void*)id, (void*)type, _async_chunk_url_done, NULL);
	if (ret) {
		free(buffer);
		fbr_cstore_io_delete_url(cstore, url, url_len, id, type);
		return;
	}
}

void
fbr_cstore_async_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_cstore_s3_chunk_url(cstore, file, chunk, url, sizeof(url));

	_async_url_delete(cstore, url, url_len, chunk->id, FBR_CSTORE_FILE_CHUNK);
}

void
fbr_cstore_async_wbuffer_send(struct fbr_cstore *cstore, struct chttp_context *request,
    char *path, struct fbr_wbuffer *wbuffer, struct fbr_cstore_op_sync *sync)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_op_sync_ok(sync);

	if (!fbr_cstore_backend_enabled(cstore)) {
		sync->done = 1;
		return;
	}

	int ret = fbr_cstore_async_queue(cstore, FBR_CSOP_WBUFFER_SEND, cstore, request, path,
		wbuffer, NULL, fbr_cstore_op_sync_done, sync);
	if (ret) {
		fbr_cstore_s3_wbuffer_send(cstore, request, path, wbuffer);
		sync->done = 1;
		return;
	}
}

void
fbr_cstore_async_index_send(struct fbr_cstore *cstore, struct chttp_context *request,
    char *path, struct fbr_writer *writer, fbr_id_t id, struct fbr_cstore_op_sync *sync)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_op_sync_ok(sync);

	if (!fbr_cstore_backend_enabled(cstore)) {
		sync->done = 1;
		return;
	}

	static_ASSERT(sizeof(void*) >= sizeof(id));

	int ret = fbr_cstore_async_queue(cstore, FBR_CSOP_INDEX_SEND, cstore, request, path,
		writer, (void*)id, fbr_cstore_op_sync_done, sync);
	if (ret) {
		fbr_cstore_s3_index_send(cstore, request, path, writer, id);
		sync->done = 1;
		return;
	}
}

void
fbr_cstore_async_index_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return;
	}

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_cstore_s3_index_url(cstore, directory, url, sizeof(url));

	_async_url_delete(cstore, url, url_len, directory->version, FBR_CSTORE_FILE_INDEX);
}

void
fbr_cstore_op_sync_init(struct fbr_cstore_op_sync *sync)
{
	assert(sync);

	fbr_zero(sync);
	sync->magic = FBR_CSTORE_OP_SYNC_MAGIC;

	pt_assert(pthread_mutex_init(&sync->lock, NULL));
	pt_assert(pthread_cond_init(&sync->cond, NULL));

	fbr_cstore_op_sync_ok(sync);
}

void
fbr_cstore_op_sync_done(struct fbr_cstore_op *op)
{
	fbr_cstore_op_ok(op);

	struct fbr_cstore_op_sync *sync = op->done_arg;
	fbr_cstore_op_sync_ok(sync);

	pt_assert(pthread_mutex_lock(&sync->lock));

	assert_zero(sync->done);
	sync->done = 1;

	pthread_cond_broadcast(&sync->cond);

	pt_assert(pthread_mutex_unlock(&sync->lock));
}

void
fbr_cstore_op_sync_wait(struct fbr_cstore_op_sync *sync)
{
	fbr_cstore_op_sync_ok(sync);

	pt_assert(pthread_mutex_lock(&sync->lock));

	if (!sync->done) {
		pt_assert(pthread_cond_wait(&sync->cond, &sync->lock));
	}

	assert(sync->done);

	pt_assert(pthread_mutex_unlock(&sync->lock));
}

void
fbr_cstore_op_sync_free(struct fbr_cstore_op_sync *sync)
{
	fbr_cstore_op_sync_ok(sync);
	assert(sync->done);

	pt_assert(pthread_mutex_destroy(&sync->lock));
	pt_assert(pthread_cond_destroy(&sync->cond));

	fbr_zero(sync);
}

const char *
fbr_cstore_async_type(enum fbr_cstore_op_type type)
{
	switch (type) {
		case FBR_CSOP_NONE:
			return "NONE";
		case FBR_CSOP_TEST:
			return "TEST";
		case FBR_CSOP_WBUFFER_WRITE:
			return "WBUFFER_WRITE";
		case FBR_CSOP_WBUFFER_SEND:
			return "WBUFFER_SEND";
		case FBR_CSOP_CHUNK_READ:
			return "CHUNK_READ";
		case FBR_CSOP_URL_DELETE:
			return "URL_DELETE";
		case FBR_CSOP_INDEX_SEND:
			return "INDEX_SEND";
		case __FBR_CSOP_END:
			break;
	}

	return "ERROR";
}
