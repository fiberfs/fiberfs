/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

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

	fbr_ZERO(async);
	pt_assert(pthread_mutex_init(&async->queue_lock, NULL));
	pt_assert(pthread_cond_init(&async->queue_ready, NULL));
	pt_assert(pthread_cond_init(&async->todo_ready, NULL));

	async->callback = _cstore_async_op;

	TAILQ_INIT(&async->todo_list);
	TAILQ_INIT(&async->active_list);
	TAILQ_INIT(&async->free_list);

	async->queue_max = FBR_CSTORE_ASYNC_OPS_DEFAULT;

	for (size_t i = 0; i < fbr_array_len(async->ops); i++) {
		struct fbr_cstore_op *op = &async->ops[i];

		op->magic = FBR_CSTORE_OP_MAGIC;
		op->type = FBR_CSOP_NONE;

		TAILQ_INSERT_TAIL(&async->free_list, op, entry);

		fbr_cstore_op_ok(op);
	}

	// TODO this needs to be configurable
	size_t i;
	for (i = 0; i < fbr_array_len(async->threads); i++) {
		pt_assert(pthread_create(&async->threads[i], NULL, _cstore_async_loop, cstore));
	}

	while (async->threads_running != i) {
		fbr_sleep_ms(0.1);
	}
}

void
fbr_cstore_async_queue(struct fbr_cstore *cstore, enum fbr_cstore_op_type type, struct fbr_fs *fs,
    void *param1, void *param2, void *param3)
{
	fbr_cstore_ok(cstore);
	assert(type > FBR_CSOP_NONE && type < __FBR_CSOP_END);

	unsigned long request_id = FBR_REQID_CS_ASYNC;
	struct fbr_request *request = fbr_request_get();
	if (request) {
		request_id = request->id;
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_ASYNC, request_id, "queue request: %s",
		fbr_cstore_async_type(type));

	struct fbr_cstore_async *async = &cstore->async;
	pt_assert(pthread_mutex_lock(&async->queue_lock));

	assert(async->queue_max);
	while (async->queue_len >= async->queue_max) {
		async->waiting++;
		//fbr_ABORT("ERROR we cannot block, we need to queue forever...");
		pt_assert(pthread_cond_wait(&async->queue_ready, &async->queue_lock));
		async->waiting--;
	}

	// TODO how do we want to exit?
	assert_zero(async->exit);

	assert_zero(TAILQ_EMPTY(&async->free_list));
	struct fbr_cstore_op *op = TAILQ_FIRST(&async->free_list);
	fbr_cstore_op_ok(op);
	assert_dev(op->type == FBR_CSOP_NONE);

	op->type = type;
	op->fs = fs;
	op->param1 = param1;
	op->param2 = param2;
	op->param3 = param3;

	TAILQ_REMOVE(&async->free_list, op, entry);
	TAILQ_INSERT_TAIL(&async->todo_list, op, entry);

	async->queue_len++;
	assert(async->queue_len <= FBR_CSTORE_ASYNC_OPS_MAX);

	pt_assert(pthread_cond_signal(&async->todo_ready));

	pt_assert(pthread_mutex_unlock(&async->queue_lock));
}

static void
_cstore_async_op(struct fbr_cstore *cstore, struct fbr_cstore_op *op)
{
	assert_dev(cstore);
	assert_dev(op);

	switch (op->type) {
		case FBR_CSOP_TEST:
			break;
		case FBR_CSOP_WBUFFER_WRITE:
			fbr_cstore_wbuffer_write(op->fs, op->param1, op->param2);
			break;
		case FBR_CSOP_CHUNK_READ:
			fbr_cstore_chunk_read(op->fs, op->param1, op->param2);
			break;
		default:
			fbr_ABORT("bad async op: %d", op->type);
	}
}

static void *
_cstore_async_loop(void *arg)
{
	assert(arg);

	struct fbr_cstore *cstore = arg;
	fbr_cstore_ok(cstore);
	struct fbr_cstore_async *async = &cstore->async;

	pt_assert(pthread_mutex_lock(&async->queue_lock));

	async->threads_running++;
	size_t thread_id = fbr_request_id_thread_gen();

	fbr_log_print(cstore->log, FBR_LOG_CS_ASYNC, thread_id, "thread running");

	while (!async->exit) {
		if (TAILQ_EMPTY(&async->todo_list)) {
			pt_assert(pthread_cond_wait(&async->todo_ready, &async->queue_lock));
			continue;
		}

		struct fbr_cstore_op *op = TAILQ_FIRST(&async->todo_list);
		fbr_cstore_op_ok(op);

		TAILQ_REMOVE(&async->todo_list, op, entry);
		TAILQ_INSERT_TAIL(&async->active_list, op, entry);

		pt_assert(pthread_mutex_unlock(&async->queue_lock));

		fbr_log_print(cstore->log, FBR_LOG_CS_ASYNC, thread_id, "calling op: %s",
			fbr_cstore_async_type(op->type));

		assert(async->callback);
		async->callback(cstore, op);

		pt_assert(pthread_mutex_lock(&async->queue_lock));

		op->type = FBR_CSOP_NONE;
		op->fs = NULL;
		op->param1 = NULL;
		op->param2 = NULL;
		op->param3 = NULL;

		TAILQ_REMOVE(&async->active_list, op, entry);
		TAILQ_INSERT_TAIL(&async->free_list, op, entry);

		async->queue_len--;
		assert(async->queue_len <= FBR_CSTORE_ASYNC_OPS_MAX);

		pt_assert(pthread_cond_signal(&async->queue_ready));
	}

	async->threads_running--;

	pt_assert(pthread_mutex_unlock(&async->queue_lock));

	return NULL;
}

void
fbr_cstore_async_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_async *async = &cstore->async;
	assert(async->threads_running == fbr_array_len(async->threads));

	pt_assert(pthread_mutex_lock(&async->queue_lock));
	async->exit = 1;
	pt_assert(pthread_cond_broadcast(&async->todo_ready));
	pt_assert(pthread_mutex_unlock(&async->queue_lock));

	for (size_t i = 0; i < fbr_array_len(async->threads); i++) {
		pt_assert(pthread_join(async->threads[i], NULL));
	}

	assert_zero(async->threads_running);
	assert_zero(async->waiting);
	assert_zero(async->queue_len);
	assert(TAILQ_EMPTY(&async->todo_list));
	assert(TAILQ_EMPTY(&async->active_list));

	pt_assert(pthread_mutex_destroy(&async->queue_lock));
	pt_assert(pthread_cond_destroy(&async->queue_ready));
	pt_assert(pthread_cond_destroy(&async->todo_ready));

	fbr_ZERO(async);
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

	fbr_cstore_async_queue(cstore, FBR_CSOP_WBUFFER_WRITE, fs, file, wbuffer, NULL);
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

	fbr_cstore_async_queue(cstore, FBR_CSOP_CHUNK_READ, fs, file, chunk, NULL);
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
		case FBR_CSOP_CHUNK_READ:
			return "CHUNK_READ";
		case __FBR_CSOP_END:
			break;
	}

	return "ERROR";
}
