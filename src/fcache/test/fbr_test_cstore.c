/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fcache/fbr_cache_store.h"

#include "test/fbr_test.h"

extern struct fbr_cache_store *_CSTORE;

static void
_test_cstore_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	fbr_cache_store_free();
}

void
fbr_cmd_cstore_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_cache_store_init();

	fbr_test_register_finish(ctx, "cstore", _test_cstore_finish);
}

#define _CSTORE_THREADS		4
#define _CSTORE_RAND_THREADS	2
#define _CSTORE_ALL_THREADS	(_CSTORE_THREADS + _CSTORE_RAND_THREADS)
#define _CSTORE_ENTRY_MAX	((1 * 1024 * 1024) + _CSTORE_THREADS)
#define _CSTORE_MAX_BYTES	(10 * 1000 * 1000)
size_t _CSTORE_THREAD_COUNT;
size_t _CSTORE_ENTRY_COUNTER;
size_t _CSTORE_READ_COUNTER;
size_t _CSTORE_BYTES_COUNTER;

static void *
_cstore_thread(void *arg)
{
	assert_zero(arg);
	assert_zero(_CSTORE_ENTRY_COUNTER);
	assert_zero(_CSTORE_READ_COUNTER);
	assert_zero(_CSTORE_BYTES_COUNTER);

	size_t id = fbr_atomic_add(&_CSTORE_THREAD_COUNT, 1);
	size_t count = _CSTORE_ENTRY_MAX / _CSTORE_THREADS;
	size_t start = count * (id - 1);
	int do_random = 0;

	if (id > _CSTORE_THREADS) {
		do_random = 1;
		fbr_test_logs(" ** Thread %zu running (random/%zu)", id, count);
	} else {
		fbr_test_logs(" ** Thread %zu running (%zu/%zu)", id, start, count);
		assert(count);
	}

	while (_CSTORE_THREAD_COUNT < _CSTORE_ALL_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_CSTORE_THREAD_COUNT == _CSTORE_ALL_THREADS);

	for (size_t i = 0; i < count; i++) {
		fbr_hash_t hash = i + start;

		if (do_random) {
			hash = random() % _CSTORE_ENTRY_MAX;
		}

		int locked = fbr_cstore_readlock(hash);
		if (!locked) {
			int exists = fbr_cstore_writelock(hash);
			if (!exists) {
				size_t bytes = random() % _CSTORE_MAX_BYTES;
				fbr_atomic_add(&_CSTORE_BYTES_COUNTER, bytes);
				fbr_atomic_add(&_CSTORE_ENTRY_COUNTER, 1);
				fbr_cstore_insert(hash, bytes);
			}
		} else {
			fbr_atomic_add(&_CSTORE_READ_COUNTER, 1);
		}

		fbr_cstore_unlock(hash);
	}

	return NULL;
}

void
fbr_cmd_cstore_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	_CSTORE_THREAD_COUNT = 0;
	_CSTORE_ENTRY_COUNTER = 0;
	_CSTORE_READ_COUNTER = 0;
	_CSTORE_BYTES_COUNTER = 0;

	fbr_test_logs("*** Starting threads");

	pthread_t threads[_CSTORE_ALL_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _cstore_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_CSTORE_THREAD_COUNT == _CSTORE_ALL_THREADS);

	fbr_test_logs("*** Threads done");

	fbr_test_logs("* cstore entries: %zu", _CSTORE_ENTRY_COUNTER);
	fbr_test_logs("* cstore reads: %zu", _CSTORE_READ_COUNTER);
	fbr_test_logs("* cstore bytes: %zu", _CSTORE_BYTES_COUNTER);

	size_t entries = 0;
	size_t bytes = 0;
	size_t slabs = 0;

	fbr_cstore_ok(_CSTORE);
	for (size_t i = 0; i < fbr_array_len(_CSTORE->heads); i++) {
		struct fbr_cstore_head *head = &_CSTORE->heads[i];
		entries += head->entries;
		bytes += head->bytes;
		struct fbr_cstore_entry_slab *slab = head->slabs;
		while (slab) {
			slabs++;
			slab = slab->next;
		}
	}

	fbr_test_logs("* _CSTORE->heads=%zu", fbr_array_len(_CSTORE->heads));
	fbr_test_logs("* _CSTORE->entries=%zu", entries);
	fbr_test_logs("* _CSTORE->slabs=%zu", slabs);
	fbr_test_logs("* _CSTORE->bytes=%zu", bytes);

	fbr_ASSERT(_CSTORE_ENTRY_COUNTER == entries, "inserted: %zu, found %zu",
		_CSTORE_ENTRY_COUNTER, entries);
	fbr_ASSERT(_CSTORE_BYTES_COUNTER == bytes, "bytes: %zu, found %zu",
		_CSTORE_BYTES_COUNTER, bytes);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_test done");
}
