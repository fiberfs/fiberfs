/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "dns/chttp_dns.h"
#include "dns/chttp_dns_cache.h"
#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"

extern long _DNS_CACHE_TTL;
extern size_t _DNS_CACHE_SIZE;

struct chttp_test_dns {
	unsigned int				magic;
#define _DNS_MAGIC				0x6CF2F95F

	char					value[256];
	char					stat_str[64];
};

static void
_dns_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(ctx->chttp_test->dns);
	assert(ctx->chttp_test->dns->magic == _DNS_MAGIC);

	fbr_zero(ctx->chttp_test->dns);
	free(ctx->chttp_test->dns);

	ctx->chttp_test->dns = NULL;
}

static void
_dns_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	if (!ctx->chttp_test->dns) {
		ctx->chttp_test->dns = calloc(1, sizeof(*ctx->chttp_test->dns));
		assert(ctx->chttp_test->dns);

		ctx->chttp_test->dns->magic = _DNS_MAGIC;

		fbr_test_register_finish(ctx, "dns", _dns_finish);
	}

	assert(ctx->chttp_test->dns->magic == _DNS_MAGIC);
}

void
chttp_test_cmd_dns_ttl(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ttl = fbr_test_parse_long(cmd->params[0].value);

	_DNS_CACHE_TTL = ttl;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "DNS ttl %ld", _DNS_CACHE_SIZE);
}

void
chttp_test_cmd_dns_cache_size(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long size = fbr_test_parse_long(cmd->params[0].value);
	assert(size > 0);

	_DNS_CACHE_SIZE = size;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "DNS cache size %zu", _DNS_CACHE_SIZE);
}

void
chttp_test_cmd_dns_lookup_or_skip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_dns_init(ctx);
	fbr_test_ERROR(cmd->param_count < 1 || cmd->param_count > 2,
		"invalid parameter count");

	long flags = 0;
	if (cmd->param_count == 2) {
		flags = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ERROR(flags < 0, "flags needs to be a positive number");
	}

	struct chttp_addr addr;
	struct chttp_addr *paddr = &addr;

	int ret = chttp_dns_resolve(&addr, cmd->params[0].value, cmd->params[0].len, 1, flags);

	if (ret) {
		fbr_test_skip(ctx);
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "cannot resolve address %s",
			cmd->params[0].value);
		return;
	}

	chttp_addr_resolved(paddr);

	chttp_sa_string(&addr.sa, ctx->chttp_test->dns->value,
		sizeof(ctx->chttp_test->dns->value), &ret);
	assert(ret == 1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "DNS result %s", ctx->chttp_test->dns->value);
}

void
chttp_test_cmd_dns_lookup(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test = fbr_test_convert(ctx);

	chttp_test_cmd_dns_lookup_or_skip(ctx, cmd);

	fbr_test_ERROR(test->skip, "dns lookup failed");
}

void
chttp_dns_cache_debug(void)
{
	chttp_dns_cache_ok();

	printf("_DNS_CACHE\n");

	struct chttp_dns_cache_entry *dns_entry, *dns_temp;
	size_t tree_count = 0, tree_sub_count = 0;
	size_t lru_count = 0, lru_sub_count = 0, free_count = 0, sub_count;

	RB_FOREACH(dns_entry, chttp_dns_cache_tree, &_DNS_CACHE.cache_tree) {
		chttp_dns_entry_ok(dns_entry);
		chttp_addr_ok(&dns_entry->addr);
		assert(dns_entry->state == CHTTP_DNS_CACHE_OK ||
			dns_entry->state == CHTTP_DNS_CACHE_STALE);

		printf("\tRB entry: '%s'\n", dns_entry->hostname);
		tree_count++;
		sub_count = 1;

		chttp_addr_ok(&dns_entry->addr);

		char name[256];
		int port;
		chttp_sa_string(&dns_entry->addr.sa, name, sizeof(name), &port);
		printf("\t\t%s:%d\n", name, port);

		dns_temp = dns_entry->next;
		while(dns_temp) {
			chttp_dns_entry_ok(dns_temp);
			chttp_addr_ok(&dns_temp->addr);
			assert(dns_temp->state == CHTTP_DNS_CACHE_OK);

			tree_sub_count++;
			sub_count++;

			chttp_addr_ok(&dns_temp->addr);
			chttp_sa_string(&dns_temp->addr.sa, name, sizeof(name), &port);
			printf("\t\t%s:%d\n", name, port);

			dns_temp = dns_temp->next;
		}

		assert(sub_count == dns_entry->length);
		assert(dns_entry->current < dns_entry->length);
	}
	printf("\tRB count: %zu (%zu)\n", tree_count, tree_count + tree_sub_count);

	TAILQ_FOREACH(dns_entry, &_DNS_CACHE.lru_list, list_entry) {
		chttp_dns_entry_ok(dns_entry);

		printf("\tLRU entry: '%s'\n", dns_entry->hostname);
		lru_count++;

		dns_temp = dns_entry->next;
		while(dns_temp) {
			chttp_dns_entry_ok(dns_temp);
			lru_sub_count++;
			dns_temp = dns_temp->next;
		}
	}
	printf("\tLRU count: %zu (%zu)\n", lru_count, lru_count + lru_sub_count);

	TAILQ_FOREACH(dns_entry, &_DNS_CACHE.free_list, list_entry) {
		free_count++;
	}
	printf("\tFREE count: %zu\n", free_count);
	printf("\tTOTAL count: %zu (%zu %zu)\n", _DNS_CACHE_SIZE,
		free_count + tree_count + tree_sub_count,
		free_count + lru_count + lru_sub_count);

	printf("\tstats.lookups: %zu\n", _DNS_CACHE.stats.lookups);
	printf("\tstats.cache_hits: %zu\n", _DNS_CACHE.stats.cache_hits);
	printf("\tstats.insertions: %zu\n", _DNS_CACHE.stats.insertions);
	printf("\tstats.dups: %zu\n", _DNS_CACHE.stats.dups);
	printf("\tstats.expired: %zu\n", _DNS_CACHE.stats.expired);
	printf("\tstats.nuked: %zu\n", _DNS_CACHE.stats.nuked);
	printf("\tstats.lru: %zu\n", _DNS_CACHE.stats.lru);
	printf("\tstats.err_too_long: %zu\n", _DNS_CACHE.stats.err_too_long);
	printf("\tstats.err_alloc: %zu\n", _DNS_CACHE.stats.err_alloc);
}

void
chttp_test_cmd_dns_debug(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_dns_init(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	struct fbr_test *test = fbr_test_convert(ctx);

	if (test->verbocity >= FBR_LOG_VERBOSE) {
		chttp_dns_cache_debug();
	}
}

char *
chttp_test_var_dns_value(struct fbr_test_context *ctx)
{
	_dns_init(ctx);

	return ctx->chttp_test->dns->value;
}

#define _DNS_STATS_NAME(name)							\
char *										\
chttp_test_var_dns_##name(struct fbr_test_context *ctx)				\
{										\
	_dns_init(ctx);								\
	chttp_dns_cache_ok();							\
										\
	fbr_bprintf(ctx->chttp_test->dns->stat_str, "%zu",			\
		_DNS_CACHE.stats.name);						\
										\
	return ctx->chttp_test->dns->stat_str;					\
}

_DNS_STATS_NAME(lookups)
_DNS_STATS_NAME(cache_hits)
_DNS_STATS_NAME(insertions)
_DNS_STATS_NAME(dups)
_DNS_STATS_NAME(expired)
_DNS_STATS_NAME(nuked)
_DNS_STATS_NAME(lru)
_DNS_STATS_NAME(err_too_long)
_DNS_STATS_NAME(err_alloc)
