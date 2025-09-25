/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_DNS_CACHE_H_INCLUDED_
#define _CHTTP_DNS_CACHE_H_INCLUDED_

#include "data/queue.h"
#include "data/tree.h"
#include "network/chttp_network.h"

#include <pthread.h>

#define CHTTP_DNS_CACHE_SIZE			100
#define CHTTP_DNS_CACHE_TTL			600
#define CHTTP_DNS_CACHE_HOST_MAX		256

enum chttp_dns_cache_state {
	CHTTP_DNS_CACHE_NONE = 0,
	CHTTP_DNS_CACHE_OK,
	CHTTP_DNS_CACHE_STALE
};

struct chttp_dns_cache_entry {
	unsigned int				magic;
#define CHTTP_DNS_CACHE_ENTRY_MAGIC		0x435870E5

	char					hostname[CHTTP_DNS_CACHE_HOST_MAX];
	size_t					length;
	size_t					current;
	double					expiration;
	enum chttp_dns_cache_state		state;

	RB_ENTRY(chttp_dns_cache_entry)		tree_entry;
	TAILQ_ENTRY(chttp_dns_cache_entry)	list_entry;

	struct chttp_dns_cache_entry		*next;

	struct chttp_addr			addr;
};

struct chttp_dns_stats {
	size_t					lookups;
	size_t					cache_hits;
	size_t					insertions;
	size_t					dups;
	size_t					expired;
	size_t					nuked;
	size_t					lru;
	size_t					err_too_long;
	size_t					err_alloc;
};

RB_HEAD(chttp_dns_cache_tree, chttp_dns_cache_entry);
TAILQ_HEAD(chttp_dns_cache_list, chttp_dns_cache_entry);

struct chttp_dns_cache {
	unsigned int				magic;
#define CHTTP_DNS_CACHE_MAGIC			0xF37F6BA4

	pthread_mutex_t				lock;

	int					initialized;

	struct chttp_dns_cache_tree		cache_tree;
	struct chttp_dns_cache_list		free_list;
	struct chttp_dns_cache_list		lru_list;

	struct chttp_dns_cache_entry		entries[CHTTP_DNS_CACHE_SIZE];

	struct chttp_dns_stats			stats;
};

RB_PROTOTYPE(chttp_dns_cache_tree, chttp_dns_cache_entry, tree_entry, _dns_cache_cmp)

extern struct chttp_dns_cache _DNS_CACHE;

#define chttp_dns_cache_ok()						\
{									\
	assert(_DNS_CACHE.magic == CHTTP_DNS_CACHE_MAGIC);		\
}
#define chttp_dns_entry_ok(dns_entry)					\
	fbr_magic_check(dns_entry, CHTTP_DNS_CACHE_ENTRY_MAGIC)

#endif /* _CHTTP_DNS_CACHE_H_INCLUDED_ */
