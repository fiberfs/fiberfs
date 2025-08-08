/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "log/test/fbr_test_log_cmds.h"

extern struct fbr_cstore *_CSTORE;

static void
_test_cstore_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	fbr_cstore_free();
}

void
fbr_test_cstore_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	char *root = fbr_test_mkdir_tmp(ctx, NULL);

	fbr_cstore_init(root);

	fbr_test_log_printer_init(ctx, root, "^");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore root: %s", _CSTORE->root);
}

void
fbr_cmd_cstore_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_cstore_init(ctx);

	fbr_test_register_finish(ctx, "cstore", _test_cstore_finish);
}

#define _CSTORE_THREADS		4
#define _CSTORE_RAND_THREADS	2
#define _CSTORE_ALL_THREADS	(_CSTORE_THREADS + _CSTORE_RAND_THREADS)
#define _CSTORE_ENTRY_MAX	((256 * 1024) + _CSTORE_THREADS)
#define _CSTORE_HASH_MAX_BYTES	(2 * 1000 * 1000)
size_t _CSTORE_MAX_BYTES;
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

		struct fbr_cstore_entry *entry = fbr_cstore_get(hash);
		if (!entry) {
			size_t bytes = random() % _CSTORE_HASH_MAX_BYTES;
			entry = fbr_cstore_insert(hash, bytes);
			if (entry) {
				fbr_cstore_entry_ok(entry);
				fbr_atomic_add(&_CSTORE_BYTES_COUNTER, bytes);
				fbr_atomic_add(&_CSTORE_ENTRY_COUNTER, 1);
				fbr_cstore_release(entry);
			} else {
				entry = fbr_cstore_get(hash);
				if (entry) {
					fbr_cstore_entry_ok(entry);
					fbr_cstore_release(entry);
				}
			}
		} else {
			fbr_cstore_entry_ok(entry);
			fbr_atomic_add(&_CSTORE_READ_COUNTER, 1);
			fbr_cstore_release(entry);
		}
	}

	return NULL;
}

static void
_cstore_test(void)
{
	fbr_test_random_seed();

	_CSTORE_THREAD_COUNT = 0;
	_CSTORE_ENTRY_COUNTER = 0;
	_CSTORE_READ_COUNTER = 0;
	_CSTORE_BYTES_COUNTER = 0;

	fbr_cstore_max_size(_CSTORE_MAX_BYTES, 1);

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

	fbr_cstore_ok(_CSTORE);
	size_t slabs = 0;
	for (size_t i = 0; i < fbr_array_len(_CSTORE->heads); i++) {
		struct fbr_cstore_head *head = &_CSTORE->heads[i];
		fbr_cstore_head_ok(head);

		struct fbr_cstore_entry_slab *slab = head->slabs;
		while (slab) {
			slabs++;
			slab = slab->next;
		}
	}

	fbr_test_logs("* _CSTORE->heads=%zu", fbr_array_len(_CSTORE->heads));
	fbr_test_logs("* _CSTORE->entries=%zu", _CSTORE->entries);
	fbr_test_logs("* _CSTORE->max_bytes=%zu", _CSTORE->max_bytes);
	fbr_test_logs("* _CSTORE->bytes=%zu", _CSTORE->bytes);
	fbr_test_logs("* _CSTORE->lru_pruned=%zu", _CSTORE->lru_pruned);
	fbr_test_logs("* _CSTORE->slabs=%zu", slabs);

	size_t entries = _CSTORE->entries + _CSTORE->lru_pruned;

	fbr_ASSERT(_CSTORE_ENTRY_COUNTER == entries, "inserted: %zu, found %zu",
		_CSTORE_ENTRY_COUNTER, entries);

	if (!_CSTORE_MAX_BYTES) {
		fbr_ASSERT(_CSTORE_BYTES_COUNTER == _CSTORE->bytes, "bytes: %zu, found %zu",
			_CSTORE_BYTES_COUNTER, _CSTORE->bytes);
	} else {
		size_t max_bytes = _CSTORE->max_bytes +
			(_CSTORE_HASH_MAX_BYTES * _CSTORE_THREAD_COUNT);
		fbr_ASSERT(_CSTORE->bytes <= max_bytes, "bytes: %zu, found %zu",
			_CSTORE_BYTES_COUNTER, max_bytes);
	}
}

void
fbr_cmd_cstore_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_CSTORE_MAX_BYTES = 0;

	_cstore_test();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_test done");
}

void
fbr_cmd_cstore_test_lru(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_CSTORE_MAX_BYTES = 200 * 1000 * 1000;

	_cstore_test();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_test_lru done");
}
