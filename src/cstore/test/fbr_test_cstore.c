/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fuse/fbr_fuse.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_sys.h"

#include "test/fbr_test.h"
#include "fbr_test_cstore_cmds.h"
#include "log/test/fbr_test_log_cmds.h"

static void
_test_cstore_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);
	assert(test_ctx->cstore);

	while(test_ctx->cstore) {
		struct fbr_test_cstore *tcstore = test_ctx->cstore;
		fbr_tcstore_ok(tcstore);

		test_ctx->cstore = tcstore->next;

		struct fbr_cstore *cstore = &tcstore->cstore;
		fbr_cstore_ok(cstore);

		fbr_cstore_free(cstore);

		fbr_zero(tcstore);
		free(tcstore);
	}

	assert_zero(test_ctx->cstore);
}

static struct fbr_cstore *
_test_cstore_init(struct fbr_test_context *ctx, const char *root, const char *log_prefix)
{
	assert_dev(ctx);

	struct fbr_test_cstore *tcstore = calloc(1, sizeof(*tcstore));
	assert(tcstore);
	tcstore->magic = FBR_TEST_CSTORE_MAGIC;

	if (!ctx->cstore) {
		ctx->cstore = tcstore;
	} else {
		struct fbr_test_cstore *last = ctx->cstore;
		fbr_tcstore_ok(last);
		while (last->next) {
			last = last->next;
			fbr_tcstore_ok(last);
		}
		last->next = tcstore;
	}

	fbr_cstore_init(&tcstore->cstore, root);

	fbr_test_log_printer_init(ctx, root, log_prefix);
	fbr_test_register_finish(ctx, "cstore", _test_cstore_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore root: %s (%s)", tcstore->cstore.root,
		log_prefix);

	return &tcstore->cstore;
}

struct fbr_test_cstore *
fbr_test_tcstore_get(struct fbr_test_context *ctx, size_t index)
{
	fbr_test_context_ok(ctx);
	assert(index < FBR_CSTORE_MAX_CSTORES);

	struct fbr_test_cstore *tcstore = ctx->cstore;
	fbr_ASSERT(tcstore, "cstore index not found");
	fbr_tcstore_ok(tcstore);

	while (index) {
		tcstore = tcstore->next;
		fbr_ASSERT(tcstore, "cstore index not found");
		fbr_tcstore_ok(tcstore);
		index--;
	}

	return tcstore;
}

struct fbr_cstore *
fbr_test_cstore_get(struct fbr_test_context *ctx, size_t index)
{
	if (!ctx) {
		ctx = fbr_test_get_ctx();
	}

	fbr_test_context_ok(ctx);

	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, index);
	assert(tcstore);
	fbr_cstore_ok(&tcstore->cstore);

	return &tcstore->cstore;
}

size_t
fbr_test_cstore_count(struct fbr_test_context *ctx)
{
	size_t count = 0;

	struct fbr_test_cstore *tcstore = ctx->cstore;
	while (tcstore) {
		count++;
		tcstore = tcstore->next;
	}

	return count;
}

static struct fbr_cstore *
_test_cstore_init_pos(struct fbr_test_context *ctx, const char *root)
{
	assert(ctx);
	assert(root);

	size_t index = fbr_test_cstore_count(ctx);

	char prefix[8];
	fbr_bprintf(prefix, "c%zu^", index);

	return _test_cstore_init(ctx, root, prefix);
}

struct fbr_cstore *
fbr_test_cstore_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	const char *root = fbr_test_mkdir_tmp(ctx, NULL);

	return _test_cstore_init_pos(ctx, root);
}

void
fbr_test_cstore_bind(struct fbr_fs *fs, int index)
{
	fbr_fs_ok(fs);
	assert_zero(fs->cstore);

	struct fbr_test_context *test_ctx = fbr_test_get_ctx();
	struct fbr_cstore *cstore = NULL;

	if (index >= 0) {
		cstore = fbr_test_cstore_get(test_ctx, index);
	} else {
		cstore = fbr_test_cstore_init(test_ctx);
	}

	fbr_cstore_ok(cstore);

	fs->cstore = cstore;
	fs->cstore_managed = 1;
}

void
fbr_test_cstore_bind_new(struct fbr_fs *fs)
{
	fbr_test_cstore_bind(fs, -1);
}

void
fbr_test_cstore_init_loader(struct fbr_test_context *ctx, struct fbr_fs *fs)
{
	fbr_test_context_ok(ctx);
	assert_zero(fbr_test_cstore_count(ctx));
	fbr_fs_ok(fs);
	assert_zero(fs->cstore);

	const char *root = fbr_test_mkdir_tmp(ctx, NULL);

	char data_path[FBR_PATH_MAX];
	fbr_bprintf(data_path, "%s/%s/", root, FBR_CSTORE_DATA_DIR);
	fbr_sys_mkdirs(data_path);

	fs->cstore = _test_cstore_init_pos(ctx, root);
	fs->cstore_managed = 1;
}

void
fbr_test_cstore_reload(struct fbr_test_context *ctx, struct fbr_fs *fs)
{
	fbr_test_context_ok(ctx);
	fbr_tcstore_ok(ctx->cstore);
	assert(fbr_test_cstore_count(ctx) == 1);
	fbr_fs_ok(fs);
	assert_zero(fs->cstore);

	struct fbr_cstore *cstore = fbr_test_cstore_get(ctx, 0);
	fbr_cstore_ok(cstore);

	char root[FBR_PATH_MAX];
	fbr_bprintf(root, "%s", cstore->root);

	_test_cstore_finish(ctx);

	fbr_test_sleep_ms(50);
	assert_zero(fbr_test_cstore_count(ctx));

	fs->cstore = _test_cstore_init(ctx, root, "c00^");
	fs->cstore_managed = 1;

	assert(fbr_test_cstore_count(ctx) == 1);
}

void
fbr_cmd_cstore_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	assert(cmd->param_count <= 1);

	size_t index = 0;

	if (cmd->param_count >= 1) {
		index = (size_t)fbr_test_parse_long(cmd->params[0].value);
		assert(index < FBR_CSTORE_MAX_CSTORES);
	}

	const char *root = fbr_test_mkdir_tmp(ctx, NULL);

	_test_cstore_init_pos(ctx, root);
}

void
fbr_test_cstore_wait(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	int max = 40;
	int count = 0;

	if (fbr_test_is_valgrind()) {
		max = 100;
	}

	while (cstore->async.queue_len && max) {
		fbr_test_sleep_ms(count);
		max--;
		count++;
	}

	assert_zero(cstore->async.queue_len);
}

static void
_cstore_debug_meta(const char *filename, struct fbr_cstore_metadata *metadata)
{
	assert_dev(filename);
	assert_dev(metadata);
	static_ASSERT(sizeof(FBR_CSTORE_DATA_DIR) == sizeof(FBR_CSTORE_META_DIR));

	fbr_zero(metadata);

	struct fbr_cstore_hashpath hashpath;
	hashpath.magic = FBR_CSTORE_HASHPATH_MAGIC;
	hashpath.length = fbr_bprintf(hashpath.value, "%s", filename);

	size_t len = hashpath.length;
	while (len > 0) {
		size_t s = sizeof(FBR_CSTORE_DATA_DIR) - 1;
		if (!strncmp(hashpath.value + len, FBR_CSTORE_DATA_DIR, s)) {
			memcpy(hashpath.value + len, FBR_CSTORE_META_DIR, s);
			break;
		}
		len--;
	}
	assert(len);

	int ret = fbr_cstore_metadata_read(&hashpath, metadata);
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
				fbr_test_logs("CSTORE_DEBUG file: %s (CHUNK %s size: %lu [%lu])",
					filename, metadata.path, metadata.size, metadata.offset);
				fbr_cstore_is_path(metadata.path);
				assert(strstr(metadata.path, FBR_FIBERFS_CHUNK_NAME));
				assert((unsigned long)stat->st_size == metadata.size);
				break;
			case FBR_CSTORE_FILE_INDEX:
				fbr_test_logs("CSTORE_DEBUG file: %s (INDEX %s gzip: %d)",
					filename, metadata.path, metadata.gzipped);
				fbr_cstore_is_path(metadata.path);
				assert(strstr(metadata.path, FBR_FIBERFS_INDEX_NAME));
				break;
			case FBR_CSTORE_FILE_ROOT:
				fbr_test_logs("CSTORE_DEBUG file: %s (ROOT %s version: %lu)",
					filename, metadata.path, metadata.etag);
				fbr_cstore_is_path(metadata.path);
				assert(strstr(metadata.path, FBR_FIBERFS_ROOT_NAME));
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
fbr_test_cstore_debug(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	fbr_test_cstore_wait(cstore);

	struct fbr_cstore_server *server = cstore->servers;
	while (server) {
		fbr_test_logs("CSTORE_DEBUG port: %d", server->port);
		server = server->next;
	}

	fbr_test_logs("CSTORE_DEBUG root: %s", cstore->root);
	fbr_test_logs("CSTORE_DEBUG entries: %zu", cstore->entries);
	fbr_test_logs("CSTORE_DEBUG bytes: %zu", cstore->bytes);
	fbr_test_logs("CSTORE_DEBUG max_bytes: %zu", cstore->max_bytes);
	fbr_test_logs("CSTORE_DEBUG pruned: %lu", cstore->stats.lru_pruned);
	fbr_test_logs("CSTORE_DEBUG removed: %lu", cstore->stats.removed);
	fbr_test_logs("CSTORE_DEBUG loaded: %lu", cstore->stats.loaded);
	fbr_test_logs("CSTORE_DEBUG lazy: %lu", cstore->stats.lazy_loaded);
	fbr_test_logs("CSTORE_DEBUG chunks: %lu", cstore->stats.wr_chunks);
	fbr_test_logs("CSTORE_DEBUG indexes: %lu", cstore->stats.wr_indexes);
	fbr_test_logs("CSTORE_DEBUG roots: %lu", cstore->stats.wr_roots);
	fbr_test_logs("CSTORE_DEBUG root updates: %lu", cstore->stats.wr_root_updates);
	fbr_test_logs("CSTORE_DEBUG chunk wr bytes: %lu", cstore->stats.wr_chunk_bytes);
	fbr_test_logs("CSTORE_DEBUG index wr bytes: %lu", cstore->stats.wr_index_bytes);
	fbr_test_logs("CSTORE_DEBUG root wr bytes: %lu", cstore->stats.wr_root_bytes);
	fbr_test_logs("CSTORE_DEBUG chunk rd bytes: %lu", cstore->stats.rd_chunk_bytes);
	fbr_test_logs("CSTORE_DEBUG chunk fetches: %lu", cstore->stats.fetch_chunks);
	fbr_test_logs("CSTORE_DEBUG workers: %lu", cstore->stats.workers);
	fbr_test_logs("CSTORE_DEBUG workers_active: %lu", cstore->stats.workers_active);
	fbr_test_logs("CSTORE_DEBUG retries: %lu", cstore->stats.retries);
	fbr_test_logs("CSTORE_DEBUG epool.waiting: %lu", cstore->epool.waiting);
	fbr_test_logs("CSTORE_DEBUG http_200: %lu", cstore->stats.http_200);
	fbr_test_logs("CSTORE_DEBUG http_400: %lu", cstore->stats.http_400);
	fbr_test_logs("CSTORE_DEBUG http_500: %lu", cstore->stats.http_500);
	fbr_test_logs("CSTORE_DEBUG http_other: %lu", cstore->stats.http_other);

	char path[FBR_PATH_MAX];
	fbr_bprintf(path, "%s/%s", cstore->root, FBR_CSTORE_DATA_DIR);

	fbr_sys_nftw(path, _cstore_debug_cb);
}

void
fbr_cmd_cstore_debug(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count <= 1);

	long index = 0;
	if (cmd->param_count >= 1) {
		index = fbr_test_parse_long(cmd->params[0].value);
	}
	assert(index >= 0);

	fbr_test_logs("CSTORE_DEBUG OBJECT: %lu", index);

	struct fbr_cstore *cstore = fbr_test_cstore_get(ctx, index);

	fbr_test_cstore_debug(cstore);
}

const char *
fbr_varf_cstore_entries(struct fbr_test_context *ctx, struct fbr_test_param *param)
{
	fbr_test_context_ok(ctx);
	assert(param && param->len);

	long index = fbr_test_parse_long(param->value);
	assert(index >= 0);

	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, index);
	assert(tcstore);
	fbr_cstore_ok(&tcstore->cstore);

	fbr_bprintf(tcstore->stat_buf, "%lu", tcstore->cstore.entries);

	return tcstore->stat_buf;
}

#define _CSTORE_TEST_STAT(var, stat)							\
const char *										\
fbr_varf_cstore_stat_##var(struct fbr_test_context *ctx, struct fbr_test_param *param)	\
{											\
	fbr_test_context_ok(ctx);							\
	assert(param);									\
	long index = fbr_test_parse_long(param->value);					\
	assert(index >= 0);								\
	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, index);		\
	assert(tcstore);								\
	fbr_cstore_ok(&tcstore->cstore);						\
	fbr_bprintf(tcstore->stat_buf, "%lu", tcstore->cstore.stats.stat);		\
	return tcstore->stat_buf;							\
}

_CSTORE_TEST_STAT(chunks, wr_chunks)
_CSTORE_TEST_STAT(indexes, wr_indexes)
_CSTORE_TEST_STAT(roots, wr_roots)
_CSTORE_TEST_STAT(chunk_write_bytes, wr_chunk_bytes)
_CSTORE_TEST_STAT(index_write_bytes, wr_index_bytes)
_CSTORE_TEST_STAT(root_write_bytes, wr_root_bytes)
_CSTORE_TEST_STAT(chunk_read_bytes, rd_chunk_bytes)

void
fbr_cmd_cstore_set_lru(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	long index = fbr_test_parse_long(cmd->params[0].value);
	long max_size = fbr_test_parse_long(cmd->params[1].value);
	assert(max_size > 0);

	struct fbr_cstore *cstore = fbr_test_cstore_get(ctx, index);

	fbr_cstore_max_size(cstore, max_size, 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_set_lru: %ld", max_size);
}

void
fbr_cmd_cstore_clear(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long index = fbr_test_parse_long(cmd->params[0].value);
	struct fbr_cstore *cstore = fbr_test_cstore_get(ctx, index);

	fbr_cstore_clear(cstore);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_clear: %ld", index);
}

#define _CSTORE_THREADS		4
#define _CSTORE_RAND_THREADS	2
#define _CSTORE_ALL_THREADS	(_CSTORE_THREADS + _CSTORE_RAND_THREADS)
#define _CSTORE_ENTRY_MAX	((256 * 1024) + _CSTORE_THREADS)
#define _CSTORE_HASH_MAX_BYTES	(2 * 1000 * 1000)
static size_t _CSTORE_MAX_BYTES;
static size_t _CSTORE_THREAD_COUNT;
static size_t _CSTORE_ENTRY_COUNTER;
static size_t _CSTORE_READ_COUNTER;
static size_t _CSTORE_BYTES_COUNTER;
static size_t _CSTORE_DELAY_COUNTER;

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

	struct fbr_cstore *cstore = fbr_test_cstore_get(NULL, 0);
	fbr_cstore_ok(cstore);

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

		struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
		if (!entry) {
			size_t bytes = (random() % _CSTORE_HASH_MAX_BYTES) + 1;
			int delay = 0;
			if (!(random() % 5)) {
				delay = 1;
			}
			entry = fbr_cstore_insert(cstore, hash, delay ? 0 : bytes, 1);
			if (entry) {
				fbr_cstore_entry_ok(entry);
				assert(entry->state == FBR_CSTORE_LOADING);
				if (delay) {
					fbr_cstore_set_size(cstore, entry, bytes);
				}
				fbr_atomic_add(&_CSTORE_BYTES_COUNTER, bytes);
				fbr_atomic_add(&_CSTORE_ENTRY_COUNTER, 1);
				fbr_atomic_add(&_CSTORE_DELAY_COUNTER, delay);
				fbr_cstore_set_ok(entry);
				fbr_cstore_release(cstore, &entry);
				assert_zero(entry);
			} else {
				entry = fbr_cstore_get(cstore, hash);
				if (entry) {
					fbr_cstore_entry_ok(entry);
					fbr_cstore_release(cstore, &entry);
					assert_zero(entry);
				}
			}
		} else {
			fbr_cstore_entry_ok(entry);
			fbr_atomic_add(&_CSTORE_READ_COUNTER, 1);

			if (random() % 10 == 0) {
				fbr_cstore_remove(cstore, &entry);
			} else {
				fbr_cstore_release(cstore, &entry);
			}

			assert_zero(entry);
		}
	}

	return NULL;
}

static void
_cstore_test(void)
{
	struct fbr_cstore *cstore = fbr_test_cstore_get(NULL, 0);
	fbr_cstore_ok(cstore);

	assert_zero(fbr_conf_get_bool("CSTORE_SERVER", FBR_CONFIG_FALSE));
	assert_zero(cstore->servers);

	fbr_test_random_seed();

	_CSTORE_THREAD_COUNT = 0;
	_CSTORE_ENTRY_COUNTER = 0;
	_CSTORE_READ_COUNTER = 0;
	_CSTORE_BYTES_COUNTER = 0;

	fbr_cstore_max_size(cstore, _CSTORE_MAX_BYTES, 1);
	cstore->delete_f = _cstore_delete_entry;

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

	fbr_cstore_ok(cstore);
	size_t slabs = 0;
	for (size_t i = 0; i < fbr_array_len(cstore->heads); i++) {
		struct fbr_cstore_head *head = &cstore->heads[i];
		fbr_cstore_head_ok(head);

		struct fbr_cstore_entry_slab *slab = head->slabs;
		while (slab) {
			slabs++;
			slab = slab->next;
		}
	}

	fbr_test_logs("* _CSTORE->heads=%zu", fbr_array_len(cstore->heads));
	fbr_test_logs("* _CSTORE->entries=%zu", cstore->entries);
	fbr_test_logs("* _CSTORE->max_bytes=%zu", cstore->max_bytes);
	fbr_test_logs("* _CSTORE->bytes=%zu", cstore->bytes);
	fbr_test_logs("* _CSTORE->lru_pruned=%lu", cstore->stats.lru_pruned);
	fbr_test_logs("* _CSTORE->slabs=%zu", slabs);
	fbr_test_logs("* _CSTORE->delayed=%lu", _CSTORE_DELAY_COUNTER);

	size_t entries = cstore->entries + cstore->stats.lru_pruned;

	fbr_ASSERT(_CSTORE_ENTRY_COUNTER == entries, "inserted: %zu, found %zu",
		_CSTORE_ENTRY_COUNTER, entries);

	if (!_CSTORE_MAX_BYTES) {
		fbr_ASSERT(_CSTORE_BYTES_COUNTER == cstore->bytes, "bytes: %zu, found %zu",
			_CSTORE_BYTES_COUNTER, cstore->bytes);
	} else {
		size_t max_bytes = cstore->max_bytes +
			(_CSTORE_HASH_MAX_BYTES * _CSTORE_THREAD_COUNT);
		fbr_ASSERT(cstore->bytes <= max_bytes, "bytes: %zu, found %zu",
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
static size_t _CSTORE_ST_THREAD_COUNT;
static size_t _CSTORE_ST_COUNTER[_CSTORE_ST_HASHES];
static size_t _CSTORE_ST_COMPLETED;
static size_t _CSTORE_ST_WAITING;

static void *
_cstore_state_thread(void *arg)
{
	assert_zero(arg);
	assert_zero(_CSTORE_ST_COMPLETED);
	assert_zero(_CSTORE_ST_WAITING);

	struct fbr_cstore *cstore = fbr_test_cstore_get(NULL, 0);
	fbr_cstore_ok(cstore);

	size_t id = fbr_atomic_add(&_CSTORE_ST_THREAD_COUNT, 1);
	while (_CSTORE_ST_THREAD_COUNT < _CSTORE_ST_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_CSTORE_ST_THREAD_COUNT == _CSTORE_ST_THREADS);

	fbr_test_logs(" ** State thread %zu running", id);

	while (_CSTORE_ST_COMPLETED < _CSTORE_ST_HASHES) {
		size_t hash = random() % _CSTORE_ST_HASHES;

		int loading = 0;

		struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
		if (!entry) {
			entry = fbr_cstore_insert(cstore, hash, 100, 1);
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


		fbr_cstore_release(cstore, &entry);
		assert_zero(entry);
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
	struct fbr_cstore *cstore = fbr_test_cstore_init(ctx);

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
		struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, i);
		fbr_cstore_entry_ok(entry);
		assert(entry->state == FBR_CSTORE_OK);
		fbr_cstore_remove(cstore, &entry);
		assert_zero(entry);
	}

	assert_zero(cstore->entries);

	fbr_test_logs("threads: %zu", _CSTORE_ST_THREAD_COUNT);
	fbr_test_logs("completed: %zu", _CSTORE_ST_COMPLETED);
	fbr_test_logs("waiting: %zu", _CSTORE_ST_WAITING);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_state_test done");
}

#define _CSTORE_WAIT_THREADS	12
#define _CSTORE_WAIT_COUNT_MAX  500
static size_t _CSTORE_WAIT_THREAD_COUNT;
static size_t _CSTORE_WAIT_FIRST_LOAD;
static size_t _CSTORE_WAIT_COUNT;
static size_t _CSTORE_WAIT_METER;

static void *
_cstore_wait_thread(void *arg)
{
	assert_zero(arg);

	struct fbr_cstore *cstore = fbr_test_cstore_get(NULL, 0);
	fbr_cstore_ok(cstore);

	size_t id = fbr_atomic_add(&_CSTORE_WAIT_THREAD_COUNT, 1);
	while (_CSTORE_WAIT_THREAD_COUNT < _CSTORE_WAIT_THREADS) {
		fbr_sleep_ms(0.01);
	}
	assert(_CSTORE_WAIT_THREAD_COUNT == _CSTORE_WAIT_THREADS);

	fbr_test_logs(" ** Wait thread %zu running", id);

	for (size_t i = 0; i < _CSTORE_WAIT_COUNT_MAX; i++) {
		struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, 1);
		if (!entry) {
			entry = fbr_cstore_insert(cstore, 1, 100, 1);
			if (!entry) {
				entry = fbr_cstore_get(cstore, 1);
				fbr_cstore_entry_ok(entry);
			} else {
				fbr_cstore_entry_ok(entry);
				assert(entry->state == FBR_CSTORE_LOADING);

				fbr_test_logs("Initial loading hit!");
				fbr_atomic_add(&_CSTORE_WAIT_FIRST_LOAD, 1);

				fbr_cstore_set_ok(entry);
				fbr_cstore_release(cstore, &entry);
				assert_zero(entry);

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
		fbr_cstore_release(cstore, &entry);
		assert_zero(entry);

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
