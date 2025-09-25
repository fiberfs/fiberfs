/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_TCP_POOL_H_INCLUDED_
#define _CHTTP_TCP_POOL_H_INCLUDED_

#include "data/queue.h"
#include "data/tree.h"

#include <pthread.h>

#define CHTTP_TCP_POOL_SIZE				30
#define CHTTP_TCP_POOL_AGE_SEC				30

struct chttp_tcp_pool_entry {
	unsigned int					magic;
#define CHTTP_TCP_POOL_ENTRY_MAGIC			0xFC286388

	struct chttp_addr				addr;

	double						expiration;

	RB_ENTRY(chttp_tcp_pool_entry)			tree_entry;
	TAILQ_ENTRY(chttp_tcp_pool_entry)		list_entry;

	struct chttp_tcp_pool_entry			*next;
};

struct chttp_pool_stats {
	size_t						lookups;
	size_t						cache_hits;
	size_t						cache_misses;
	size_t						insertions;
	size_t						expired;
	size_t						deleted;
	size_t						nuked;
	size_t						lru;
	size_t						err_alloc;
};

RB_HEAD(chttp_tcp_pool_tree, chttp_tcp_pool_entry);
TAILQ_HEAD(chttp_tcp_pool_list, chttp_tcp_pool_entry);

struct chttp_tcp_pool {
	unsigned int					magic;
#define CHTTP_TCP_POOL_MAGIC				0x288EA1AC

	pthread_mutex_t					lock;

	int						initialized;

	struct chttp_tcp_pool_tree			pool_tree;
	struct chttp_tcp_pool_list			free_list;
	struct chttp_tcp_pool_list			lru_list;

	struct chttp_tcp_pool_entry			entries[CHTTP_TCP_POOL_SIZE];

	struct chttp_pool_stats				stats;
};

extern struct chttp_tcp_pool _TCP_POOL;

int chttp_tcp_pool_lookup(struct chttp_addr *addr);
void chttp_tcp_pool_store(struct chttp_addr *addr);
void chttp_tcp_pool_close(void);

RB_PROTOTYPE(chttp_tcp_pool_tree, chttp_tcp_pool_entry, tree_entry, _tcp_pool_cmp)

#define chttp_tcp_pool_ok()						\
{									\
	assert(_TCP_POOL.magic == CHTTP_TCP_POOL_MAGIC);		\
}
#define chttp_pool_entry_ok(pool_entry)					\
	fbr_magic_check(pool_entry, CHTTP_TCP_POOL_ENTRY_MAGIC)

#endif /* _CHTTP_TCP_POOL_H_INCLUDED_ */
