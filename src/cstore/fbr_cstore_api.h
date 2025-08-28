/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_STORE_H_INCLUDED_
#define _FBR_CSTORE_STORE_H_INCLUDED_

#include <pthread.h>

#include "fiberfs.h"
#include "data/queue.h"
#include "data/tree.h"

#define FBR_CSTORE_HEAD_COUNT			64
#define FBR_CSTORE_SLAB_SIZE			128

enum fbr_cstore_entry_state {
	FBR_CSTORE_ENTRY_NONE = 0,
	FBR_CSTORE_ENTRY_FREE,
	FBR_CSTORE_ENTRY_USED
};

struct fbr_cstore_entry {
	unsigned				magic;
#define FBR_CSTORE_ENTRY_MAGIC			0xA59C372B

	enum fbr_cstore_entry_state		state;

	fbr_hash_t				hash;
	size_t					bytes;

	fbr_refcount_t				refcount;
	unsigned int				in_lru:1;

	RB_ENTRY(fbr_cstore_entry)		tree_entry;
	TAILQ_ENTRY(fbr_cstore_entry)		list_entry;
};

struct fbr_cstore_entry_slab {
	struct fbr_cstore_entry			entries[FBR_CSTORE_SLAB_SIZE];
	size_t					count;
	struct fbr_cstore_entry_slab		*next;
};

RB_HEAD(fbr_cstore_tree, fbr_cstore_entry);
TAILQ_HEAD(fbr_cstore_list, fbr_cstore_entry);

struct fbr_cstore_head {
	unsigned				magic;
#define FBR_CSTORE_HEAD_MAGIC			0xA249385F

	struct fbr_cstore_tree			tree;
	struct fbr_cstore_list			lru_list;
	struct fbr_cstore_list			free_list;

	struct fbr_cstore_entry_slab		*slabs;

	pthread_mutex_t				lock;
};

struct fbr_cstore {
	unsigned				magic;
#define FBR_CSTORE_MAGIC			0xC8747276

	struct fbr_cstore_head			heads[FBR_CSTORE_HEAD_COUNT];

	struct fbr_log				*log;

	char					root[FBR_PATH_MAX];

	size_t					max_bytes;
	int					do_lru;

	size_t					entries;
	size_t					bytes;
	size_t					lru_pruned;
};

void fbr_cstore_init(struct fbr_cstore *cstore, const char *root_path);
void fbr_cstore_max_size(struct fbr_cstore *cstore, size_t max_bytes, int lru);
struct fbr_cstore_entry *fbr_cstore_get(struct fbr_cstore *cstore, fbr_hash_t hash);
struct fbr_cstore_entry *fbr_cstore_insert(struct fbr_cstore *cstore, fbr_hash_t hash,
	size_t bytes);
void fbr_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry);
void fbr_cstore_free(struct fbr_cstore *cstore);

#define fbr_cstore_ok(cstore)			fbr_magic_check(cstore, FBR_CSTORE_MAGIC)
#define fbr_cstore_head_ok(head)		fbr_magic_check(head, FBR_CSTORE_HEAD_MAGIC)
#define fbr_cstore_entry_ok(entry)		fbr_magic_check(entry, FBR_CSTORE_ENTRY_MAGIC)

#endif /* _FBR_CSTORE_STORE_H_INCLUDED_ */
