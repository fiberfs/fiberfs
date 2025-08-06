/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CACHE_STORE_H_INCLUDED_
#define _FBR_CACHE_STORE_H_INCLUDED_

#include <pthread.h>
#include <stdint.h>

#include "fbr_cache.h"
#include "data/queue.h"
#include "data/tree.h"

#define FBR_CSTORE_HEAD_COUNT			1024

struct fbr_cstore_entry {
	unsigned				magic;
#define FBR_CSTORE_ENTRY_MAGIC			0xA59C372B

	fbr_chash_t				hash;

	RB_ENTRY(fbr_cstore_entry)		entry;
	TAILQ_ENTRY(fbr_cstore_entry)		lru_entry;
};

RB_HEAD(fbr_cstore_tree, fbr_cstore_entry);
TAILQ_HEAD(fbr_cstore_lru_list, fbr_cstore_entry);

struct fbr_cstore_head {
	unsigned				magic;
#define FBR_CSTORE_HEAD_MAGIC			0xA249385F

	struct fbr_cstore_tree			tree;
	pthread_rwlock_t			lock;

	size_t					count;
	size_t					bytes;
};

struct fbr_cache_store {
	unsigned				magic;
#define FBR_CSTORE_MAGIC			0xC8747276

	struct fbr_cstore_head			heads[FBR_CSTORE_HEAD_COUNT];

	struct fbr_cstore_lru_list		lru;
	pthread_mutex_t				lru_lock;
};

void fbr_cache_store_init(void);
void fbr_cache_store_free(void);

#define fbr_cstore_ok(cstore)			fbr_magic_check(cstore, FBR_CSTORE_MAGIC)
#define fbr_cstore_head_ok(head)		fbr_magic_check(head, FBR_CSTORE_HEAD_MAGIC)
#define fbr_cstore_entry_ok(entry)		fbr_magic_check(entry, FBR_CSTORE_ENTRY_MAGIC)

#endif /* _FBR_CACHE_STORE_H_INCLUDED_ */
