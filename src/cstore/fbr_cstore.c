/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "log/fbr_log.h"

static int _cstore_entry_cmp(const struct fbr_cstore_entry *e1, const struct fbr_cstore_entry *e2);

RB_GENERATE_STATIC(fbr_cstore_tree, fbr_cstore_entry, tree_entry, _cstore_entry_cmp)

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
		entry->alloc = FBR_CSTORE_ENTRY_FREE;

		TAILQ_INSERT_TAIL(&head->free_list, entry, list_entry);

		fbr_cstore_entry_ok(entry);
	}

	slab->next = head->slabs;
	head->slabs = slab;
}

void
fbr_cstore_init(struct fbr_cstore *cstore, const char *root_path)
{
	assert(cstore);

	cstore->magic = FBR_CSTORE_MAGIC;

	for (size_t i = 0; i < fbr_array_len(cstore->heads); i++) {
		struct fbr_cstore_head *head = &cstore->heads[i];
		fbr_object_empty(head);

		head->magic = FBR_CSTORE_HEAD_MAGIC;

		RB_INIT(&head->tree);
		TAILQ_INIT(&head->lru_list);
		TAILQ_INIT(&head->free_list);
		pt_assert(pthread_mutex_init(&head->lock, NULL));

		_cstore_add_slab(head);
		assert_dev(!TAILQ_EMPTY(&head->free_list));

		fbr_cstore_head_ok(head);
	}

	size_t path_len = strlen(root_path);
	assert(path_len < sizeof(cstore->root));
	memcpy(cstore->root, root_path, path_len + 1);

	cstore->log = fbr_log_alloc(cstore->root, fbr_log_default_size());
	fbr_log_ok(cstore->log);

	fbr_log_print(cstore->log, FBR_LOG_CSTORE, FBR_REQID_CSTORE, "init");

	fbr_cstore_ok(cstore);
}

void
fbr_cstore_max_size(struct fbr_cstore *cstore, size_t max_bytes, int lru)
{
	fbr_cstore_ok(cstore);

	cstore->max_bytes = max_bytes;
	cstore->do_lru = lru;
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
_cstore_get_entry(struct fbr_cstore *cstore, struct fbr_cstore_head *head, fbr_hash_t hash)
{
	assert(cstore);
	fbr_cstore_head_ok(head);

	if (TAILQ_EMPTY(&head->free_list)) {
		_cstore_add_slab(head);
		assert_dev(!TAILQ_EMPTY(&head->free_list));
	}

	struct fbr_cstore_entry *entry = TAILQ_FIRST(&head->free_list);
	fbr_cstore_entry_ok(entry);
	assert(entry->alloc == FBR_CSTORE_ENTRY_FREE);

	entry->hash = hash;
	entry->alloc = FBR_CSTORE_ENTRY_USED;
	entry->refcount = 1; // LRU takes a ref
	entry->in_lru = 1;

	TAILQ_REMOVE(&head->free_list, entry, list_entry);
	TAILQ_INSERT_HEAD(&head->lru_list, entry, list_entry);
	assert_zero(RB_INSERT(fbr_cstore_tree, &head->tree, entry));

	fbr_atomic_add(&cstore->entries, 1);

	return entry;
}

struct fbr_cstore_head *
_cstore_get_head(struct fbr_cstore *cstore, fbr_hash_t hash)
{
	assert_dev(cstore);

	struct fbr_cstore_head *head = &cstore->heads[hash % fbr_array_len(cstore->heads)];
	fbr_cstore_head_ok(head);

	return head;
}

struct fbr_cstore_entry *
fbr_cstore_get(struct fbr_cstore *cstore, fbr_hash_t hash)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_head *head = _cstore_get_head(cstore, hash);
	pt_assert(pthread_mutex_lock(&head->lock));
	fbr_cstore_head_ok(head);

	struct fbr_cstore_entry find;
	find.magic = FBR_CSTORE_ENTRY_MAGIC;
	find.hash = hash;

	struct fbr_cstore_entry *entry = RB_FIND(fbr_cstore_tree, &head->tree, &find);
	if (!entry) {
		pthread_mutex_unlock(&head->lock);
		return NULL;
	}

	fbr_cstore_entry_ok(entry);
	assert(entry->alloc == FBR_CSTORE_ENTRY_USED);
	assert(entry->refcount);

	entry->refcount++;
	assert(entry->refcount);

	if (entry->in_lru) {
		if (TAILQ_FIRST(&head->lru_list) != entry) {
			TAILQ_REMOVE(&head->lru_list, entry, list_entry);
			TAILQ_INSERT_HEAD(&head->lru_list, entry, list_entry);
		}
	}

	pt_assert(pthread_mutex_unlock(&head->lock));

	return entry;
}

static void
_cstore_entry_free(struct fbr_cstore *cstore, struct fbr_cstore_head *head,
    struct fbr_cstore_entry *entry)
{
	assert_dev(cstore);
	assert_dev(head);
	assert_dev(entry);
	assert_zero(entry->refcount);
	assert_zero(entry->in_lru);

	size_t bytes = entry->bytes;

	entry->alloc = FBR_CSTORE_ENTRY_FREE;
	entry->hash = 0;
	entry->bytes = 0;

	void *ret = RB_REMOVE(fbr_cstore_tree, &head->tree, entry);
	assert(ret == entry);

	TAILQ_INSERT_HEAD(&head->free_list, entry, list_entry);

	fbr_atomic_sub(&cstore->bytes, bytes);
	fbr_atomic_sub(&cstore->entries, 1);
}

static int
_cstore_full(struct fbr_cstore *cstore, size_t new_bytes)
{
	assert_dev(cstore);

	if (!cstore->max_bytes) {
		return 0;
	}

	size_t total_bytes = cstore->bytes + new_bytes;
	if (total_bytes > cstore->max_bytes) {
		return 1;
	}

	return 0;
}

static void
_cstore_lru_prune(struct fbr_cstore *cstore, struct fbr_cstore_head *head, size_t new_bytes)
{
	assert_dev(cstore);
	assert_dev(cstore->do_lru);
	assert_dev(head);

	if (!cstore->max_bytes) {
		return;
	}

	size_t count = 0;

	while (_cstore_full(cstore, new_bytes)) {
		if (TAILQ_EMPTY(&head->lru_list) || count > 5) {
			break;
		}
		count++;

		struct fbr_cstore_entry *entry = TAILQ_LAST(&head->lru_list, fbr_cstore_list);
		fbr_cstore_entry_ok(entry);
		assert(entry->alloc == FBR_CSTORE_ENTRY_USED);
		assert(entry->in_lru);

		TAILQ_REMOVE(&head->lru_list, entry, list_entry);

		assert(entry->refcount);
		entry->refcount--;
		entry->in_lru = 0;

		if (!entry->refcount) {
			_cstore_entry_free(cstore, head, entry);
		}

		fbr_atomic_add(&cstore->lru_pruned, 1);
	}
}

struct fbr_cstore_entry *
fbr_cstore_insert(struct fbr_cstore *cstore, fbr_hash_t hash, size_t bytes)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_head *head = _cstore_get_head(cstore, hash);
	pt_assert(pthread_mutex_lock(&head->lock));
	fbr_cstore_head_ok(head);

	struct fbr_cstore_entry find;
	find.magic = FBR_CSTORE_ENTRY_MAGIC;
	find.hash = hash;

	struct fbr_cstore_entry *entry = RB_FIND(fbr_cstore_tree, &head->tree, &find);
	if (entry) {
		fbr_cstore_entry_ok(entry);
		assert_dev(entry->alloc == FBR_CSTORE_ENTRY_USED);
		assert_dev(entry->refcount);

		pthread_mutex_unlock(&head->lock);

		return NULL;
	}

	if (cstore->do_lru) {
		_cstore_lru_prune(cstore, head, bytes);
	} else if (_cstore_full(cstore, bytes)) {
		pthread_mutex_unlock(&head->lock);
		return NULL;
	}

	entry = _cstore_get_entry(cstore, head, hash);
	assert_dev(entry->alloc == FBR_CSTORE_ENTRY_USED);
	assert_dev(entry->in_lru);

	// Caller takes a ref
	entry->refcount++;
	assert(entry->refcount);

	entry->bytes = bytes;
	fbr_atomic_add(&cstore->bytes, bytes);

	pt_assert(pthread_mutex_unlock(&head->lock));

	return entry;
}

void
fbr_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_entry_ok(entry);
	assert(entry->alloc == FBR_CSTORE_ENTRY_USED);

	struct fbr_cstore_head *head = _cstore_get_head(cstore, entry->hash);
	pt_assert(pthread_mutex_lock(&head->lock));
	fbr_cstore_head_ok(head);

	assert(entry->refcount);
	entry->refcount--;

	if (entry->refcount) {
		pt_assert(pthread_mutex_unlock(&head->lock));
		return;
	}

	_cstore_entry_free(cstore, head, entry);

	pt_assert(pthread_mutex_unlock(&head->lock));
}

void
fbr_cstore_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	for (size_t i = 0; i < fbr_array_len(cstore->heads); i++) {
		struct fbr_cstore_head *head = &cstore->heads[i];
		fbr_cstore_head_ok(head);

		while (head->slabs) {
			struct fbr_cstore_entry_slab *slab = head->slabs;
			head->slabs = slab->next;

			for (size_t i = 0; i < slab->count; i++) {
				struct fbr_cstore_entry *entry = &slab->entries[i];
				assert(entry->alloc);
				if (entry->alloc == FBR_CSTORE_ENTRY_FREE) {
					TAILQ_REMOVE(&head->free_list, entry, list_entry);
				} else {
					assert(entry->alloc == FBR_CSTORE_ENTRY_USED);
					assert_dev(entry->refcount == 1);
					assert_dev(entry->in_lru);
					TAILQ_REMOVE(&head->lru_list, entry, list_entry);
					void *ret = RB_REMOVE(fbr_cstore_tree, &head->tree, entry);
					assert(ret == entry);

					cstore->entries--;
					cstore->bytes -= entry->bytes;
				}
			}

			fbr_ZERO(slab);
			free(slab);
		}

		pt_assert(pthread_mutex_destroy(&head->lock));

		assert(TAILQ_EMPTY(&head->free_list));
		assert(TAILQ_EMPTY(&head->lru_list));
		assert(RB_EMPTY(&head->tree));

		fbr_ZERO(head);
	}

	assert_zero(cstore->entries);
	assert_zero(cstore->bytes);

	fbr_log_free(cstore->log);

	fbr_ZERO(cstore);
}
