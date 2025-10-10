/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "fbr_test_cstore_cmds.h"
#include "log/test/fbr_test_log_cmds.h"

extern struct fbr_cstore *_CSTORE;

#define _ASYNC_TEST_MAX		2500
#define _ASYNC_TEST_THREADS	8
size_t _ASYNC_TEST_QUEUED;
size_t _ASYNC_TEST_ERROR;
size_t _ASYNC_TEST_CALLED;

static void
_test_async_op(struct fbr_cstore *cstore, struct fbr_cstore_op *op)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_op_ok(op);

	fbr_test_sleep_ms(random() % 2);

	fbr_atomic_add(&_ASYNC_TEST_CALLED, 1);
}

static void *
_cstore_state_thread(void *arg)
{
	assert_zero(arg);

	while (_ASYNC_TEST_QUEUED < _ASYNC_TEST_MAX) {
		enum fbr_cstore_op_priority priority = random() % FBR_CSTORE_OP_HIGHEST + 1;
		int ret = fbr_cstore_async_queue(_CSTORE, FBR_CSOP_TEST, NULL, NULL, NULL, NULL,
			NULL, NULL, priority);
		if (ret) {
			fbr_atomic_add(&_ASYNC_TEST_ERROR, 1);
			fbr_test_sleep_ms(1);
		} else {
			fbr_atomic_add(&_ASYNC_TEST_QUEUED, 1);
		}
	}

	return NULL;
}

void
fbr_cmd_cstore_async_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	fbr_test_cstore_init(ctx);
	fbr_cstore_ok(_CSTORE);

	fbr_test_log_printer_silent(1);

	_CSTORE->async.callback = _test_async_op;
	assert_zero(_ASYNC_TEST_QUEUED);
	assert_zero(_ASYNC_TEST_CALLED);

	pthread_t threads[_ASYNC_TEST_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _cstore_state_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}

	size_t max = 1000;
	while (_ASYNC_TEST_CALLED < _ASYNC_TEST_QUEUED && max) {
		fbr_test_sleep_ms(1);
		max--;
	}

	fbr_test_logs("queued: %zu", _ASYNC_TEST_QUEUED);
	fbr_test_logs("called: %zu", _ASYNC_TEST_CALLED);
	fbr_test_logs("error: %zu", _ASYNC_TEST_ERROR);

	assert(_ASYNC_TEST_CALLED >= _ASYNC_TEST_MAX);
	assert(_ASYNC_TEST_CALLED == _ASYNC_TEST_QUEUED);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_async_test done");
}
