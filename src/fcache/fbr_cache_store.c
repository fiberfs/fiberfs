/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_cache_store.h"

struct fbr_cache_store __CSTORE;
struct fbr_cache_store *_CSTORE = &__CSTORE;

#define _cstore_ok()	fbr_cstore_ok(_CSTORE)

static int _cstore_entry_cmp(const struct fbr_cstore_entry *e1, const struct fbr_cstore_entry *e2);

RB_GENERATE_STATIC(fbr_cstore_tree, fbr_cstore_entry, entry, _cstore_entry_cmp)

static void
_cstore_add_slab(struct fbr_cstore_head *head)
{
	assert_dev(head);

	struct fbr_cstore_entry_slab *slab = calloc(1, sizeof(*slab));
	assert(slab);

	slab->count = fbr_array_len(slab->entries);

	for (size_t i = 0; i < slab->count; i++) {
		struct fbr_cstore_entry *entry = &slab->entries[i];

		entry->magic = FBR_CSTORE_ENTRY_MAGIC;
		entry->free = 1;

		TAILQ_INSERT_TAIL(&head->free_list, entry, list_entry);

		fbr_cstore_entry_ok(entry);
	}

	if (!head->slabs) {
		head->slabs = slab;
	} else {
		struct fbr_cstore_entry_slab *prev = head->slabs;
		while (prev->next) {
			prev = prev->next;
		}
		prev->next = slab;
	}
}

void
fbr_cache_store_init(void)
{
	fbr_object_empty(_CSTORE);

	_CSTORE->magic = FBR_CSTORE_MAGIC;

	for (size_t i = 0; i < fbr_array_len(_CSTORE->heads); i++) {
		struct fbr_cstore_head *head = &_CSTORE->heads[i];
		fbr_object_empty(head);

		head->magic = FBR_CSTORE_HEAD_MAGIC;

		RB_INIT(&head->tree);
		TAILQ_INIT(&head->lru_list);
		TAILQ_INIT(&head->free_list);
		pt_assert(pthread_rwlock_init(&head->lock, NULL));

		_cstore_add_slab(head);

		fbr_cstore_head_ok(head);
	}

	_cstore_ok();
}

static int
_cstore_entry_cmp(const struct fbr_cstore_entry *e1, const struct fbr_cstore_entry *e2)
{
	fbr_cstore_entry_ok(e1);
	fbr_cstore_entry_ok(e2);

	if (e1->hash > e2->hash) {
		return 1;
	} else if (e1->hash < e2->hash) {
		return -1;
	}

	return 0;
}

void
fbr_cache_store_free(void)
{
	_cstore_ok();

	for (size_t i = 0; i < fbr_array_len(_CSTORE->heads); i++) {
		struct fbr_cstore_head *head = &_CSTORE->heads[i];
		fbr_cstore_head_ok(head);

		while (head->slabs) {
			struct fbr_cstore_entry_slab *slab = head->slabs;
			head->slabs = slab->next;

			for (size_t i = 0; i < slab->count; i++) {
				struct fbr_cstore_entry *entry = &slab->entries[i];
				assert(entry->free + entry->used == 1);
				if (entry->free) {
					TAILQ_REMOVE(&head->free_list, entry, list_entry);
				} else {
					TAILQ_REMOVE(&head->lru_list, entry, list_entry);
					void *ret = RB_REMOVE(fbr_cstore_tree, &head->tree, entry);
					assert(ret == entry);

					head->count--;
					head->bytes -= entry->bytes;
				}
			}

			fbr_ZERO(slab);
			free(slab);
		}

		pt_assert(pthread_rwlock_destroy(&head->lock));

		assert(TAILQ_EMPTY(&head->free_list));
		assert(TAILQ_EMPTY(&head->lru_list));
		assert(RB_EMPTY(&head->tree));

		assert_zero(head->count);
		assert_zero(head->bytes);

		fbr_ZERO(head);
	}

	fbr_ZERO(_CSTORE);
}
