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

extern struct fbr_cstore *_CSTORE;

#define _ASYNC_TEST_MAX		50
#define _ASYNC_TEST_THREADS	8
size_t _ASYNC_TEST_COUNT;
size_t _ASYNC_TEST_CALLED;

static void
_test_async_op(struct fbr_cstore *cstore, struct fbr_cstore_op *op)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_op_ok(op);

	fbr_test_logs("async callback: %s queue_len: %zu waiting: %zu",
		fbr_cstore_async_type(op->type), cstore->async.queue_len, cstore->async.waiting);

	fbr_test_sleep_ms(random() % 2);

	fbr_atomic_add(&_ASYNC_TEST_CALLED, 1);
}

static void *
_cstore_state_thread(void *arg)
{
	assert_zero(arg);

	while (1) {
		size_t count = fbr_atomic_add(&_ASYNC_TEST_COUNT, 1);
		if (count > _ASYNC_TEST_MAX) {
			break;
		}

		fbr_cstore_async_queue(_CSTORE, FBR_CSOP_TEST, NULL, NULL, NULL, NULL);
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

	_CSTORE->async.callback = _test_async_op;
	assert_zero(_ASYNC_TEST_COUNT);
	assert_zero(_ASYNC_TEST_CALLED);

	pthread_t threads[_ASYNC_TEST_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _cstore_state_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}

	while (_ASYNC_TEST_CALLED < _ASYNC_TEST_MAX) {
		fbr_test_sleep_ms(1);
	}
	assert (_ASYNC_TEST_CALLED == _ASYNC_TEST_MAX);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_async_test done");
}
