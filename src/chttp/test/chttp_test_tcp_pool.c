/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "network/chttp_network.h"
#include "network/chttp_tcp_pool.h"

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

extern double _TCP_POOL_AGE_SEC;
extern size_t _TCP_POOL_SIZE;

struct chttp_test_tcp_pool {
	unsigned int				magic;
#define _TCP_POOL_MAGIC				0xB1C2DA94

	char					stat_str[64];
};

static void
_tcp_pool_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(ctx->chttp_test->tcp_pool);
	assert(ctx->chttp_test->tcp_pool->magic == _TCP_POOL_MAGIC);

	fbr_zero(ctx->chttp_test->tcp_pool);
	free(ctx->chttp_test->tcp_pool);

	ctx->chttp_test->tcp_pool = NULL;
}

static void
_tcp_pool_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	if (!ctx->chttp_test->tcp_pool) {
		ctx->chttp_test->tcp_pool = calloc(1, sizeof(*ctx->chttp_test->tcp_pool));
		assert(ctx->chttp_test->tcp_pool);

		ctx->chttp_test->tcp_pool->magic = _TCP_POOL_MAGIC;

		fbr_test_register_finish(ctx, "tcp_pool", _tcp_pool_finish);

		fbr_test_log(ctx, FBR_LOG_VERBOSE, "tcp pool initialized");
	}

	assert(ctx->chttp_test->tcp_pool->magic == _TCP_POOL_MAGIC);
}

void
chttp_test_cmd_tcp_pool_age_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ttl = fbr_test_parse_long(cmd->params[0].value);

	_TCP_POOL_AGE_SEC = ((double)ttl) / 1000;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "tcp pool age %lf", _TCP_POOL_AGE_SEC);
}

void
chttp_test_cmd_tcp_pool_size(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long size = fbr_test_parse_long(cmd->params[0].value);
	assert(size > 0);

	_TCP_POOL_SIZE = size;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "tcp pool size %zu", _TCP_POOL_SIZE);
}

void
chttp_test_cmd_tcp_pool_fake_connect(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int fd;

	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	chttp_context_ok(ctx->chttp_test->chttp);
	fbr_test_ERROR_param_count(cmd, 0);

	fd = open("/dev/null", O_RDWR);
	assert(fd >= 0);

	ctx->chttp_test->chttp->addr.sock = fd;
	ctx->chttp_test->chttp->addr.state = CHTTP_ADDR_CONNECTED;
	ctx->chttp_test->chttp->state = CHTTP_STATE_IDLE;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "tcp pool faked connection");
}

static void
_tcp_pool_debug(void)
{
	chttp_tcp_pool_ok();

	printf("_TCP_POOL\n");

	struct chttp_tcp_pool_entry *entry, *temp;
	size_t free_size = 0, lru_size = 0, pool_size = 0;

	TAILQ_FOREACH(entry, &_TCP_POOL.free_list, list_entry) {
		assert_zero(entry->magic);
		free_size++;
	}

	printf("\t_TCP_POOL.free_list=%zu\n", free_size);

	char host[256];
	int port;

	TAILQ_FOREACH(entry, &_TCP_POOL.lru_list, list_entry) {
		chttp_pool_entry_ok(entry);
		chttp_addr_connected(&entry->addr);

		lru_size++;

		chttp_sa_string(&entry->addr.sa, host, sizeof(host), &port);

		printf("\t_TCP_POOL.lru_list: %s:%d age=%lf *ptr=%p\n", host, port,
			entry->expiration - fbr_get_time(), (void*)entry);
	}

	printf("\t_TCP_POOL.lru_list=%zu\n", lru_size);

	RB_FOREACH_SAFE(entry, chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, temp) {
		size_t count = 0;

		while (entry) {
			chttp_pool_entry_ok(entry);
			chttp_addr_connected(&entry->addr);

			pool_size++;

			chttp_sa_string(&entry->addr.sa, host, sizeof(host), &port);

			printf("\t_TCP_POOL.pool_tree: %zu %s:%d age=%lf *ptr=%p fd=%d\n",
				count, host, port, entry->expiration - fbr_get_time(),
				(void*)entry, entry->addr.sock);

			entry = entry->next;
			count++;
		}
	}

	printf("\t_TCP_POOL.pool_tree=%zu\n", pool_size);

	printf("\tstats.lookups: %zu\n", _TCP_POOL.stats.lookups);
	printf("\tstats.cache_hits: %zu\n", _TCP_POOL.stats.cache_hits);
	printf("\tstats.cache_misses: %zu\n", _TCP_POOL.stats.cache_misses);
	printf("\tstats.insertions: %zu\n", _TCP_POOL.stats.insertions);
	printf("\tstats.expired: %zu\n", _TCP_POOL.stats.expired);
	printf("\tstats.deleted: %zu\n", _TCP_POOL.stats.deleted);
	printf("\tstats.nuked: %zu\n", _TCP_POOL.stats.nuked);
	printf("\tstats.lru: %zu\n", _TCP_POOL.stats.lru);
	printf("\tstats.err_alloc: %zu\n", _TCP_POOL.stats.err_alloc);
}

void
chttp_test_cmd_tcp_pool_debug(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR_param_count(cmd, 0);
	struct fbr_test *test = fbr_test_convert(ctx);

	_tcp_pool_init(ctx);

	if (test->verbocity >= FBR_LOG_VERBOSE) {
		_tcp_pool_debug();
	}
}

#define _TCP_POOL_STATS_NAME(name)						\
char *										\
chttp_test_var_tcp_pool_##name(struct fbr_test_context *ctx)			\
{										\
	_tcp_pool_init(ctx);							\
	chttp_tcp_pool_ok();							\
										\
	fbr_bprintf(ctx->chttp_test->tcp_pool->stat_str, "%zu",			\
		_TCP_POOL.stats.name);						\
										\
	return ctx->chttp_test->tcp_pool->stat_str;				\
}

_TCP_POOL_STATS_NAME(lookups)
_TCP_POOL_STATS_NAME(cache_hits)
_TCP_POOL_STATS_NAME(cache_misses)
_TCP_POOL_STATS_NAME(insertions)
_TCP_POOL_STATS_NAME(expired)
_TCP_POOL_STATS_NAME(deleted)
_TCP_POOL_STATS_NAME(nuked)
_TCP_POOL_STATS_NAME(lru)
_TCP_POOL_STATS_NAME(err_alloc)
