/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

struct {
	unsigned int				magic;
#define _WORKER_POOL_MAGIC			0xB8F45940

	pthread_mutex_t				lock;

	TAILQ_HEAD(, fbr_cstore_worker)		alloc_list;
	size_t					alloc_size;
	size_t					active;
} __WORKER_POOL = {
	_WORKER_POOL_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	TAILQ_HEAD_INITIALIZER(__WORKER_POOL.alloc_list),
	0, 0
}, *_WORKER_POOL = &__WORKER_POOL;

#define _worker_pool_ok()	\
	fbr_magic_check(_WORKER_POOL, _WORKER_POOL_MAGIC)

static unsigned int _WORKER_KEY_COUNT;
static pthread_key_t _WORKER_KEY;

void
fbr_cstore_worker_key_init(void)
{
	unsigned int key_count = fbr_atomic_add(&_WORKER_KEY_COUNT, 1);
	assert(key_count);

	if (key_count > 1) {
		return;
	}

	pt_assert(pthread_key_create(&_WORKER_KEY, NULL));
}

void
fbr_cstore_worker_key_free(void)
{
	_worker_pool_ok();
	assert(_WORKER_KEY_COUNT);
	unsigned int key_count = fbr_atomic_sub(&_WORKER_KEY_COUNT, 1);

	if (key_count) {
		return;
	}

	assert_zero(_WORKER_POOL->active);
	assert_zero(_WORKER_POOL->alloc_size);

	pt_assert(pthread_key_delete(_WORKER_KEY));
}

struct fbr_cstore_worker *
fbr_cstore_worker_alloc(struct fbr_cstore *cstore, const char *name)
{
	fbr_cstore_ok(cstore);
	_worker_pool_ok();
	assert(_WORKER_KEY_COUNT);
	assert_zero_dev(fbr_cstore_worker_get());

	size_t workspace_size = fbr_workspace_size();
	struct fbr_cstore_worker *worker = calloc(1, sizeof(*worker) + workspace_size);
	assert(worker);

	worker->magic = FBR_CSTORE_WORKER_MAGIC;
	worker->name = name;
	worker->workspace = fbr_workspace_init(worker + 1, workspace_size);
	worker->cstore = cstore;
	worker->thread = pthread_self();

	pt_assert(pthread_setspecific(_WORKER_KEY, worker));

	pt_assert(pthread_mutex_lock(&_WORKER_POOL->lock));

	TAILQ_INSERT_TAIL(&_WORKER_POOL->alloc_list, worker, entry);
	_WORKER_POOL->alloc_size++;
	cstore->stats.workers++;

	pt_assert(pthread_mutex_unlock(&_WORKER_POOL->lock));

	return worker;
}

struct fbr_cstore_worker *
fbr_cstore_worker_get(void)
{
	if (!_WORKER_KEY_COUNT) {
		return NULL;
	}

	struct fbr_cstore_worker *worker = pthread_getspecific(_WORKER_KEY);
	if (!worker) {
		return NULL;
	}

	fbr_cstore_worker_ok(worker);

	return worker;
}

void
fbr_cstore_worker_init(struct fbr_cstore_worker *worker, struct fbr_log *log)
{
	fbr_cstore_worker_ok(worker);
	fbr_cstore_ok(worker->cstore);
	fbr_workspace_ok(worker->workspace);
	assert_dev(worker->workspace->free >= FBR_WORKSPACE_MIN_SIZE);
	assert_zero_dev(worker->workspace->pos);
	assert_zero(worker->request_id);
	assert_dev(fbr_cstore_worker_get() == worker);

	worker->time_start = fbr_get_time();
	worker->request_id = fbr_request_id_gen();

	fbr_wlog_workspace_alloc(worker, log);

	fbr_atomic_add(&_WORKER_POOL->active, 1);
	fbr_atomic_add(&worker->cstore->stats.workers_active, 1);
}

void
fbr_cstore_worker_finish(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_cstore_ok(worker->cstore);
	assert_dev(worker->request_id);

	worker->time_start = 0;
	worker->request_id = 0;

	fbr_rlog_free(&worker->rlog);
	fbr_workspace_reset(worker->workspace);

	assert(_WORKER_POOL->active);
	assert(worker->cstore->stats.workers_active);

	fbr_atomic_sub(&_WORKER_POOL->active, 1);
	fbr_atomic_sub(&worker->cstore->stats.workers_active, 1);
}

void
fbr_cstore_worker_free(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_cstore_ok(worker->cstore);
	_worker_pool_ok();

	assert_dev(fbr_cstore_worker_get() == worker);
	pt_assert(pthread_setspecific(_WORKER_KEY, NULL));
	assert_zero_dev(fbr_cstore_worker_get());

	fbr_workspace_free(worker->workspace);

	pt_assert(pthread_mutex_lock(&_WORKER_POOL->lock));

	assert(_WORKER_POOL->alloc_size);

	TAILQ_REMOVE(&_WORKER_POOL->alloc_list, worker, entry);
	_WORKER_POOL->alloc_size--;
	worker->cstore->stats.workers--;

	pt_assert(pthread_mutex_unlock(&_WORKER_POOL->lock));

	fbr_zero(worker);
	free(worker);
}
