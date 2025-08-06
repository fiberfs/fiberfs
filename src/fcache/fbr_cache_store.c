/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
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
		entry->state = FBR_CSTORE_ENTRY_FREE;

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
		pt_assert(pthread_mutex_init(&head->lru_lock, NULL));

		_cstore_add_slab(head);
		assert_dev(!TAILQ_EMPTY(&head->free_list));

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

static struct fbr_cstore_entry *
_cstore_get_entry(struct fbr_cstore_head *head, fbr_hash_t hash)
{
	fbr_cstore_head_ok(head);
	assert(head->write_locked);

	if (TAILQ_EMPTY(&head->free_list)) {
		_cstore_add_slab(head);
		assert_dev(!TAILQ_EMPTY(&head->free_list));
	}

	struct fbr_cstore_entry *entry = TAILQ_FIRST(&head->free_list);
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_ENTRY_FREE);

	entry->hash = hash;
	entry->state = FBR_CSTORE_ENTRY_USED;

	TAILQ_REMOVE(&head->free_list, entry, list_entry);
	TAILQ_INSERT_HEAD(&head->lru_list, entry, list_entry);
	assert_zero(RB_INSERT(fbr_cstore_tree, &head->tree, entry));

	head->entries++;

	return entry;
}

struct fbr_cstore_head *
_cstore_get_head(fbr_hash_t hash)
{
	_cstore_ok();

	struct fbr_cstore_head *head = &_CSTORE->heads[hash % fbr_array_len(_CSTORE->heads)];
	fbr_cstore_head_ok(head);

	return head;
}

int
fbr_cstore_readlock(fbr_hash_t hash)
{
	_cstore_ok();

	struct fbr_cstore_head *head = _cstore_get_head(hash);

	pt_assert(pthread_rwlock_rdlock(&head->lock));
	fbr_cstore_head_ok(head);

	struct fbr_cstore_entry find;
	find.magic = FBR_CSTORE_ENTRY_MAGIC;
	find.hash = hash;

	struct fbr_cstore_entry *entry = RB_FIND(fbr_cstore_tree, &head->tree, &find);
	if (!entry) {
		pthread_rwlock_unlock(&head->lock);
		return 0;
	}

	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_ENTRY_USED);

	pt_assert(pthread_mutex_lock(&head->lru_lock));

	if (TAILQ_FIRST(&head->lru_list) != entry) {
		TAILQ_REMOVE(&head->lru_list, entry, list_entry);
		TAILQ_INSERT_HEAD(&head->lru_list, entry, list_entry);
	}

	pt_assert(pthread_mutex_unlock(&head->lru_lock));

	return 1;
}

int
fbr_cstore_writelock(fbr_hash_t hash)
{
	_cstore_ok();

	struct fbr_cstore_head *head = _cstore_get_head(hash);

	pt_assert(pthread_rwlock_wrlock(&head->lock));
	fbr_cstore_head_ok(head);

	assert_zero(head->write_locked);
	head->write_locked = 1;

	struct fbr_cstore_entry find;
	find.magic = FBR_CSTORE_ENTRY_MAGIC;
	find.hash = hash;

	struct fbr_cstore_entry *entry = RB_FIND(fbr_cstore_tree, &head->tree, &find);
	if (entry) {
		fbr_cstore_entry_ok(entry);
		assert(entry->state == FBR_CSTORE_ENTRY_USED);

		return 1;
	}

	return 0;
}

void
fbr_cstore_insert(fbr_hash_t hash, size_t bytes)
{
	_cstore_ok();

	struct fbr_cstore_head *head = _cstore_get_head(hash);
	assert(head->write_locked);

	struct fbr_cstore_entry *entry = _cstore_get_entry(head, hash);
	assert_dev(entry->state == FBR_CSTORE_ENTRY_USED);

	entry->bytes = bytes;
	head->bytes += bytes;
}

void
fbr_cstore_unlock(fbr_hash_t hash)
{
	_cstore_ok();

	struct fbr_cstore_head *head = _cstore_get_head(hash);

	head->write_locked = 0;

	pthread_rwlock_unlock(&head->lock);
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
				assert(entry->state);
				if (entry->state == FBR_CSTORE_ENTRY_FREE) {
					TAILQ_REMOVE(&head->free_list, entry, list_entry);
				} else {
					assert(entry->state == FBR_CSTORE_ENTRY_USED);
					TAILQ_REMOVE(&head->lru_list, entry, list_entry);
					void *ret = RB_REMOVE(fbr_cstore_tree, &head->tree, entry);
					assert(ret == entry);

					head->entries--;
					head->bytes -= entry->bytes;
				}
			}

			fbr_ZERO(slab);
			free(slab);
		}

		pt_assert(pthread_rwlock_destroy(&head->lock));
		pt_assert(pthread_mutex_destroy(&head->lru_lock));

		assert(TAILQ_EMPTY(&head->free_list));
		assert(TAILQ_EMPTY(&head->lru_list));
		assert(RB_EMPTY(&head->tree));

		assert_zero(head->entries);
		assert_zero(head->bytes);

		fbr_ZERO(head);
	}

	fbr_ZERO(_CSTORE);
}
