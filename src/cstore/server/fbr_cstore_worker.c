/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

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
	assert(_WORKER_KEY_COUNT);
	unsigned int key_count = fbr_atomic_sub(&_WORKER_KEY_COUNT, 1);

	if (key_count) {
		return;
	}

	pt_assert(pthread_key_delete(_WORKER_KEY));
}

struct fbr_cstore_worker *
fbr_cstore_worker_alloc(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);
	assert(_WORKER_KEY_COUNT);
	assert_zero_dev(fbr_cstore_worker_get());

	size_t workspace_size = fbr_workspace_size();
	struct fbr_cstore_worker *worker = calloc(1, sizeof(*worker) + workspace_size);
	assert(worker);

	worker->magic = FBR_CSTORE_WORKER_MAGIC;
	worker->workspace = fbr_workspace_init(worker + 1, workspace_size);
	worker->cstore = cstore;

	pt_assert(pthread_setspecific(_WORKER_KEY, worker));

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
fbr_cstore_worker_init(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_workspace_ok(worker->workspace);
	assert_dev(worker->workspace->free >= FBR_WORKSPACE_MIN_SIZE);
	assert_zero_dev(worker->workspace->pos);
	assert_zero(worker->request_id);
	assert_dev(fbr_cstore_worker_get() == worker);

	worker->time_start = fbr_get_time();
	worker->request_id = fbr_request_id_gen();

	fbr_wlog_workspace_alloc(worker);
}

void
fbr_cstore_worker_finish(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	assert_dev(worker->request_id);

	worker->time_start = 0;
	worker->request_id = 0;

	fbr_rlog_free(&worker->rlog);
	fbr_workspace_reset(worker->workspace);
}

void
fbr_cstore_worker_free(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);

	assert_dev(fbr_cstore_worker_get() == worker);
	pt_assert(pthread_setspecific(_WORKER_KEY, NULL));
	assert_zero_dev(fbr_cstore_worker_get());

	fbr_workspace_free(worker->workspace);

	fbr_zero(worker);
	free(worker);
}
