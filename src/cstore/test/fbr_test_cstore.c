/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fuse/fbr_fuse.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

#include "test/fbr_test.h"
#include "log/test/fbr_test_log_cmds.h"

struct fbr_cstore __CSTORE;
struct fbr_cstore *_CSTORE = &__CSTORE;

static char _CSTORE_STAT_BUF[32];

static void
_test_cstore_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	if (fbr_fuse_has_context()) {
		struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
		if (fuse_ctx->cstore == _CSTORE) {
			fuse_ctx->cstore = NULL;
		}
	}

	fbr_cstore_free(_CSTORE);
	_CSTORE = NULL;
}

static void
_test_cstore_init(struct fbr_test_context *ctx, const char *root, const char *log_prefix,
    int finish)
{
	assert_dev(ctx);
	fbr_object_empty(_CSTORE);

	fbr_cstore_init(_CSTORE, root);

	fbr_test_log_printer_init(ctx, root, log_prefix);

	if (finish) {
		fbr_test_register_finish(ctx, "cstore", _test_cstore_finish);
	}

	if (fbr_fuse_has_context()) {
		struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
		assert_zero(fuse_ctx->cstore);
		fuse_ctx->cstore = _CSTORE;
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore root: %s", _CSTORE->root);
}

void
fbr_test_cstore_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	char *root = fbr_test_mkdir_tmp(ctx, NULL);

	_test_cstore_init(ctx, root, "^", 1);
}

void
fbr_test_cstore_init_loader(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	char *root = fbr_test_mkdir_tmp(ctx, NULL);

	char data_path[FBR_PATH_MAX];
	int ret = snprintf(data_path, sizeof(data_path), "%s/%s/", root, FBR_CSTORE_DATA_DIR);
	assert(ret > 0 && (size_t)ret < sizeof(data_path));
	fbr_sys_mkdirs(data_path);

	_test_cstore_init(ctx, root, "^", 1);
}

void
fbr_test_cstore_reload(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_cstore_ok(_CSTORE);

	char root[FBR_PATH_MAX];
	size_t ret = snprintf(root, sizeof(root), "%s", _CSTORE->root);
	assert(ret < sizeof(root));

	_test_cstore_finish(ctx);

	fbr_test_sleep_ms(50);

	_CSTORE = &__CSTORE;
	_test_cstore_init(ctx, root, "&", 0);
}

void
fbr_cmd_cstore_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_cstore_init(ctx);
}

static void
_test_cstore_wait(void)
{
	fbr_cstore_ok(_CSTORE);

	int max = 40;

	while (_CSTORE->async.queue_len && max) {
		fbr_test_sleep_ms(25);
		max--;
	}

	assert_zero(_CSTORE->async.queue_len);
}

static void
_cstore_debug_meta(const char *filename, struct fbr_cstore_metadata *metadata)
{
	assert_dev(filename);
	assert_dev(metadata);
	static_ASSERT(sizeof(FBR_CSTORE_DATA_DIR) == sizeof(FBR_CSTORE_META_DIR));

	fbr_ZERO(metadata);

	char meta_path[FBR_PATH_MAX];
	int ret = snprintf(meta_path, sizeof(meta_path), "%s", filename);
	assert(ret > 0 && (size_t)ret < sizeof(meta_path));

	while (ret > 0) {
		size_t s = sizeof(FBR_CSTORE_DATA_DIR) - 1;
		if (!strncmp(meta_path + ret, FBR_CSTORE_DATA_DIR, s)) {
			memcpy(meta_path + ret, FBR_CSTORE_META_DIR, s);
			break;
		}
		ret--;
	}
	assert(ret);

	ret = fbr_cstore_metadata_read(meta_path, metadata);
	//assert_zero(ret);
	if (ret) {
		metadata->type = FBR_CSTORE_FILE_NONE;
	}
}

static int
_cstore_debug_cb(const char *filename, const struct stat *stat, int flag, struct FTW *info)
{
	(void)stat;
	(void)info;

	struct fbr_cstore_metadata metadata;

	switch (flag) {
		case FTW_F:
		case FTW_SL:
			_cstore_debug_meta(filename, &metadata);
			switch (metadata.type) {
			case FBR_CSTORE_FILE_CHUNK:
				fbr_test_logs("CSTORE_DEBUG file: %s (CHUNK %s size: %lu)",
					filename, metadata.path, metadata.size);
				break;
			case FBR_CSTORE_FILE_INDEX:
				fbr_test_logs("CSTORE_DEBUG file: %s (INDEX %s gzip: %d)",
					filename, metadata.path, metadata.gzipped);
				break;
			case FBR_CSTORE_FILE_ROOT:
				fbr_test_logs("CSTORE_DEBUG file: %s (ROOT %s)",
					filename, metadata.path);
				assert_zero(metadata.gzipped);
				break;
			default:
				fbr_ABORT("CSTORE_DEBUG file: %s (BAD metadata error: %d)",
					filename, metadata.error);
			}
			break;
		default:
			break;
	}

	return 0;
}

void
fbr_test_cstore_debug(void)
{
	fbr_cstore_ok(_CSTORE);

	_test_cstore_wait();

	fbr_test_logs("CSTORE_DEBUG root: %s", _CSTORE->root);
	fbr_test_logs("CSTORE_DEBUG entries: %zu", _CSTORE->entries);
	fbr_test_logs("CSTORE_DEBUG bytes: %zu", _CSTORE->bytes);
	fbr_test_logs("CSTORE_DEBUG max_bytes: %zu", _CSTORE->max_bytes);
	fbr_test_logs("CSTORE_DEBUG pruned: %lu", _CSTORE->stats.lru_pruned);
	fbr_test_logs("CSTORE_DEBUG removed: %lu", _CSTORE->stats.removed);
	fbr_test_logs("CSTORE_DEBUG loaded: %lu", _CSTORE->stats.loaded);
	fbr_test_logs("CSTORE_DEBUG lazy: %lu", _CSTORE->stats.lazy_loaded);
	fbr_test_logs("CSTORE_DEBUG chunks: %lu", _CSTORE->stats.wr_chunks);
	fbr_test_logs("CSTORE_DEBUG indexes: %lu", _CSTORE->stats.wr_indexes);
	fbr_test_logs("CSTORE_DEBUG roots: %lu", _CSTORE->stats.wr_roots);

	char path[FBR_PATH_MAX];
	size_t ret = snprintf(path, sizeof(path), "%s/%s",
		_CSTORE->root,
		FBR_CSTORE_DATA_DIR);
	assert(ret < sizeof(path));

	fbr_sys_nftw(path, _cstore_debug_cb);
}

void
fbr_cmd_cstore_debug(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_cstore_debug();
}

fbr_stats_t
fbr_test_cstore_stat_chunks(void)
{
	fbr_cstore_ok(_CSTORE);
	return _CSTORE->stats.wr_chunks;
}

fbr_stats_t
fbr_test_cstore_stat_indexes(void)
{
	fbr_cstore_ok(_CSTORE);
	return _CSTORE->stats.wr_indexes;
}

fbr_stats_t
fbr_test_cstore_stat_roots(void)
{
	fbr_cstore_ok(_CSTORE);
	return _CSTORE->stats.wr_roots;
}

char *
fbr_var_cstore_stat_indexes(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	int ret = snprintf(_CSTORE_STAT_BUF, sizeof(_CSTORE_STAT_BUF), "%lu",
		fbr_test_cstore_stat_indexes());
	assert(ret > 0 && (size_t)ret < sizeof(_CSTORE_STAT_BUF));
	return _CSTORE_STAT_BUF;
}

char *
fbr_var_cstore_stat_roots(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	int ret = snprintf(_CSTORE_STAT_BUF, sizeof(_CSTORE_STAT_BUF), "%lu",
		fbr_test_cstore_stat_roots());
	assert(ret > 0 && (size_t)ret < sizeof(_CSTORE_STAT_BUF));
	return _CSTORE_STAT_BUF;
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

static void
_cstore_delete_entry(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_entry_ok(entry);

	fbr_atomic_sub(&_CSTORE_BYTES_COUNTER, entry->bytes);
}

static void *
_cstore_thread(void *arg)
{
	assert_zero(arg);
	assert_zero(_CSTORE_ENTRY_COUNTER);
	assert_zero(_CSTORE_READ_COUNTER);
	assert_zero(_CSTORE_BYTES_COUNTER);
	fbr_cstore_ok(_CSTORE);

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

		struct fbr_cstore_entry *entry = fbr_cstore_get(_CSTORE, hash);
		if (!entry) {
			size_t bytes = (random() % _CSTORE_HASH_MAX_BYTES) + 1;
			entry = fbr_cstore_insert(_CSTORE, hash, bytes, 1);
			if (entry) {
				fbr_cstore_entry_ok(entry);
				assert(entry->state == FBR_CSTORE_LOADING);
				fbr_atomic_add(&_CSTORE_BYTES_COUNTER, bytes);
				fbr_atomic_add(&_CSTORE_ENTRY_COUNTER, 1);
				fbr_cstore_set_ok(entry);
				fbr_cstore_release(_CSTORE, entry);
			} else {
				entry = fbr_cstore_get(_CSTORE, hash);
				if (entry) {
					fbr_cstore_entry_ok(entry);
					fbr_cstore_release(_CSTORE, entry);
				}
			}
		} else {
			fbr_cstore_entry_ok(entry);
			fbr_atomic_add(&_CSTORE_READ_COUNTER, 1);

			if (random() % 10 == 0) {
				fbr_cstore_remove(_CSTORE, entry);
			} else {
				fbr_cstore_release(_CSTORE, entry);
			}
		}
	}

	return NULL;
}

static void
_cstore_test(void)
{
	fbr_cstore_ok(_CSTORE);

	assert_zero(_CSTORE_CONFIG.server);
	assert_zero(_CSTORE->servers);

	fbr_test_random_seed();

	_CSTORE_THREAD_COUNT = 0;
	_CSTORE_ENTRY_COUNTER = 0;
	_CSTORE_READ_COUNTER = 0;
	_CSTORE_BYTES_COUNTER = 0;

	fbr_cstore_max_size(_CSTORE, _CSTORE_MAX_BYTES, 1);
	_CSTORE->delete_f = _cstore_delete_entry;

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
	fbr_test_logs("* _CSTORE->lru_pruned=%lu", _CSTORE->stats.lru_pruned);
	fbr_test_logs("* _CSTORE->slabs=%zu", slabs);

	size_t entries = _CSTORE->entries + _CSTORE->stats.lru_pruned;

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

#define _CSTORE_ST_THREADS	40
#define _CSTORE_ST_HASHES	10
size_t _CSTORE_ST_THREAD_COUNT;
size_t _CSTORE_ST_COUNTER[_CSTORE_ST_HASHES];
size_t _CSTORE_ST_COMPLETED;
size_t _CSTORE_ST_WAITING;

static void *
_cstore_state_thread(void *arg)
{
	assert_zero(arg);
	fbr_cstore_ok(_CSTORE);
	assert_zero(_CSTORE_ST_COMPLETED);
	assert_zero(_CSTORE_ST_WAITING);

	size_t id = fbr_atomic_add(&_CSTORE_ST_THREAD_COUNT, 1);
	while (_CSTORE_ST_THREAD_COUNT < _CSTORE_ST_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_CSTORE_ST_THREAD_COUNT == _CSTORE_ST_THREADS);

	fbr_test_logs(" ** State thread %zu running", id);

	while (_CSTORE_ST_COMPLETED < _CSTORE_ST_HASHES) {
		size_t hash = random() % _CSTORE_ST_HASHES;

		int loading = 0;

		struct fbr_cstore_entry *entry = fbr_cstore_get(_CSTORE, hash);
		if (!entry) {
			entry = fbr_cstore_insert(_CSTORE, hash, 100, 1);
			if (!entry) {
				continue;
			}
			loading = 1;
			assert(entry->state == FBR_CSTORE_LOADING);
		}
		fbr_cstore_entry_ok(entry);

		assert(hash < fbr_array_len(_CSTORE_ST_COUNTER));
		size_t state = fbr_atomic_add(&_CSTORE_ST_COUNTER[hash], 1);
		assert(state < 1000 * 1000 * 1000);

		if (state >= 5) {
			if (loading) {
				assert(entry->state == FBR_CSTORE_LOADING);
				fbr_cstore_set_error(entry);
			}
			enum fbr_cstore_state state = fbr_cstore_wait_loading(entry);
			assert(state == FBR_CSTORE_NONE || state == FBR_CSTORE_OK);
			fbr_atomic_add(&_CSTORE_ST_WAITING, 1);
			fbr_test_sleep_ms(10);
		} else if (state == 4) {
			fbr_test_sleep_ms(random() % 50);
			if (!loading) {
				loading = fbr_cstore_set_loading(entry);
			}
			assert(loading);
			fbr_ASSERT(entry->state == FBR_CSTORE_LOADING,
				"found final state %d", entry->state);
			fbr_cstore_set_ok(entry);
			fbr_atomic_add(&_CSTORE_ST_COMPLETED, 1);
		} else {
			assert(state > 0 && state < 4);
			if (!loading) {
				loading = fbr_cstore_set_loading(entry);
			}
			fbr_ASSERT(entry->state >= FBR_CSTORE_LOADING,
				"found state %d", entry->state);

			if (loading) {
				assert(entry->state == FBR_CSTORE_LOADING);
				fbr_test_sleep_ms(random() % 25);
				fbr_cstore_set_error(entry);
			}
		}


		fbr_cstore_release(_CSTORE, entry);
	}

	return NULL;
}

void
fbr_cmd_cstore_state_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	assert_zero(_CSTORE_ST_THREAD_COUNT);
	static_ASSERT(_CSTORE_ST_HASHES < _CSTORE_ST_THREADS);

	fbr_test_random_seed();
	fbr_test_cstore_init(ctx);

	fbr_test_logs("*** Starting threads");

	pthread_t threads[_CSTORE_ST_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _cstore_state_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_CSTORE_ST_THREAD_COUNT == _CSTORE_ST_THREADS);

	fbr_test_logs("*** Threads done");

	for (size_t i = 0; i < _CSTORE_ST_HASHES; i++) {
		assert(_CSTORE_ST_COUNTER[i] >= 4);
		struct fbr_cstore_entry *entry = fbr_cstore_get(_CSTORE, i);
		fbr_cstore_entry_ok(entry);
		assert(entry->state == FBR_CSTORE_OK);
		fbr_cstore_remove(_CSTORE, entry);
	}

	assert_zero(_CSTORE->entries);

	fbr_test_logs("threads: %zu", _CSTORE_ST_THREAD_COUNT);
	fbr_test_logs("completed: %zu", _CSTORE_ST_COMPLETED);
	fbr_test_logs("waiting: %zu", _CSTORE_ST_WAITING);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_state_test done");
}

#define _CSTORE_WAIT_THREADS	12
#define _CSTORE_WAIT_COUNT_MAX  500
size_t _CSTORE_WAIT_THREAD_COUNT;
size_t _CSTORE_WAIT_FIRST_LOAD;
size_t _CSTORE_WAIT_COUNT;
size_t _CSTORE_WAIT_METER;

static void *
_cstore_wait_thread(void *arg)
{
	assert_zero(arg);
	fbr_cstore_ok(_CSTORE);

	size_t id = fbr_atomic_add(&_CSTORE_WAIT_THREAD_COUNT, 1);
	while (_CSTORE_WAIT_THREAD_COUNT < _CSTORE_WAIT_THREADS) {
		fbr_sleep_ms(0.01);
	}
	assert(_CSTORE_WAIT_THREAD_COUNT == _CSTORE_WAIT_THREADS);

	fbr_test_logs(" ** Wait thread %zu running", id);

	for (size_t i = 0; i < _CSTORE_WAIT_COUNT_MAX; i++) {
		struct fbr_cstore_entry *entry = fbr_cstore_get(_CSTORE, 1);
		if (!entry) {
			entry = fbr_cstore_insert(_CSTORE, 1, 100, 1);
			if (!entry) {
				entry = fbr_cstore_get(_CSTORE, 1);
				fbr_cstore_entry_ok(entry);
			} else {
				fbr_cstore_entry_ok(entry);
				assert(entry->state == FBR_CSTORE_LOADING);

				fbr_test_logs("Initial loading hit!");
				fbr_atomic_add(&_CSTORE_WAIT_FIRST_LOAD, 1);

				fbr_cstore_set_ok(entry);
				fbr_cstore_release(_CSTORE, entry);

				continue;
			}
		} else {
			int loading = fbr_cstore_set_loading(entry);
			assert_zero(loading);
		}

		fbr_cstore_reset_loading(entry);
		assert(entry->state == FBR_CSTORE_LOADING);

		assert_zero(_CSTORE_WAIT_METER);
		fbr_atomic_add(&_CSTORE_WAIT_METER, 1);
		fbr_sleep_ms(0.001);
		assert(_CSTORE_WAIT_METER == 1);

		_CSTORE_WAIT_COUNT++;
		_CSTORE_WAIT_METER--;

		fbr_cstore_set_ok(entry);
		fbr_cstore_release(_CSTORE, entry);
		fbr_sleep_ms(0.01);
	}

	return NULL;
}

void
fbr_cmd_cstore_wait_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	assert_zero(_CSTORE_WAIT_THREAD_COUNT);
	assert_zero(_CSTORE_WAIT_FIRST_LOAD);
	assert_zero(_CSTORE_WAIT_COUNT);
	assert_zero(_CSTORE_WAIT_METER);

	fbr_test_random_seed();
	fbr_test_cstore_init(ctx);

	fbr_test_logs("*** Starting threads");

	pthread_t threads[_CSTORE_WAIT_THREADS];

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_create(&threads[i], NULL, _cstore_wait_thread, NULL));
	}

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}
	assert(_CSTORE_WAIT_THREAD_COUNT == _CSTORE_WAIT_THREADS);

	fbr_test_logs("*** Threads done");

	fbr_test_logs("_CSTORE_WAIT_THREAD_COUNT: %zu", _CSTORE_WAIT_THREAD_COUNT);
	fbr_test_logs("_CSTORE_WAIT_FIRST_LOAD: %zu", _CSTORE_WAIT_FIRST_LOAD);
	fbr_test_logs("_CSTORE_WAIT_COUNT: %zu", _CSTORE_WAIT_COUNT);
	fbr_test_logs("_CSTORE_WAIT_METER: %zu", _CSTORE_WAIT_METER);

	assert(_CSTORE_WAIT_FIRST_LOAD == 1);
	assert(_CSTORE_WAIT_COUNT);
	assert_zero(_CSTORE_WAIT_METER);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_wait_test done");
}
