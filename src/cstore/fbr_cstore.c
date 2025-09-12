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
#include "utils/fbr_sys.h"

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

		assert_dev(entry->state == FBR_CSTORE_NONE);
		pt_assert(pthread_mutex_init(&entry->state_lock, NULL));
		pt_assert(pthread_cond_init(&entry->state_cond, NULL));

		TAILQ_INSERT_TAIL(&head->free_list, entry, list_entry);

		fbr_cstore_entry_ok(entry);
	}

	slab->next = head->slabs;
	head->slabs = slab;
}

struct fbr_cstore *
fbr_cstore_alloc(const char *root_path)
{
	assert(root_path);

	struct fbr_cstore *cstore = malloc(sizeof(*cstore));
	assert(cstore);

	fbr_cstore_init(cstore, root_path);

	return cstore;
}

void
fbr_cstore_init(struct fbr_cstore *cstore, const char *root_path)
{
	assert(cstore);
	assert(root_path);
	assert(fbr_sys_isdir(root_path));

	fbr_ZERO(cstore);
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

	cstore->delete_f = fbr_cstore_delete_entry;

	fbr_log_print(cstore->log, FBR_LOG_CSTORE, FBR_REQID_CSTORE, "init");

	fbr_cstore_async_init(cstore);

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
	assert_dev(entry->state == FBR_CSTORE_NONE);

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
		pt_assert(pthread_mutex_unlock(&head->lock));
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
	assert_zero(entry->state == FBR_CSTORE_LOADING);

	void *ret = RB_REMOVE(fbr_cstore_tree, &head->tree, entry);
	assert(ret == entry);

	fbr_atomic_sub(&cstore->bytes, entry->bytes);
	fbr_atomic_sub(&cstore->entries, 1);

	// TODO async?
	if (cstore->delete_f) {
		cstore->delete_f(cstore, entry);
	}

	entry->type = FBR_CSTORE_FILE_NONE;
	entry->alloc = FBR_CSTORE_ENTRY_FREE;
	entry->state = FBR_CSTORE_NONE;
	entry->hash = 0;
	entry->bytes = 0;

	TAILQ_INSERT_HEAD(&head->free_list, entry, list_entry);
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
_cstore_lru_delete(struct fbr_cstore *cstore, struct fbr_cstore_head *head,
    struct fbr_cstore_entry *entry)
{
	assert_dev(cstore);
	assert_dev(head);
	assert_dev(entry);
	assert_dev(entry->in_lru);

	TAILQ_REMOVE(&head->lru_list, entry, list_entry);

	assert(entry->refcount);
	entry->refcount--;
	entry->in_lru = 0;

	fbr_atomic_add(&cstore->lru_pruned, 1);
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

		_cstore_lru_delete(cstore, head, entry);

		if (!entry->refcount) {
			_cstore_entry_free(cstore, head, entry);
		}
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

		pt_assert(pthread_mutex_unlock(&head->lock));

		return NULL;
	}

	if (cstore->do_lru) {
		_cstore_lru_prune(cstore, head, bytes);
	} else if (_cstore_full(cstore, bytes)) {
		pt_assert(pthread_mutex_unlock(&head->lock));
		return NULL;
	}

	entry = _cstore_get_entry(cstore, head, hash);
	assert_dev(entry->type == FBR_CSTORE_FILE_NONE);
	assert_dev(entry->alloc == FBR_CSTORE_ENTRY_USED);
	assert_dev(entry->state == FBR_CSTORE_NONE);
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
fbr_cstore_set_loading(struct fbr_cstore_entry *entry)
{
	fbr_cstore_entry_ok(entry);

	pt_assert(pthread_mutex_lock(&entry->state_lock));

	while (entry->state != FBR_CSTORE_OK) {
		switch (entry->state) {
		case FBR_CSTORE_NONE:
			entry->state = FBR_CSTORE_LOADING;
			pt_assert(pthread_mutex_unlock(&entry->state_lock));
			return;
		case FBR_CSTORE_LOADING:
			pt_assert(pthread_cond_wait(&entry->state_cond, &entry->state_lock));
			break;
		default:
			fbr_ABORT("Invalid state: %d", entry->state);
		}
	}

	pt_assert(pthread_mutex_unlock(&entry->state_lock));
}

enum fbr_cstore_state
fbr_cstore_wait_loading(struct fbr_cstore_entry *entry)
{
	fbr_cstore_entry_ok(entry);

	pt_assert(pthread_mutex_lock(&entry->state_lock));

	while (entry->state == FBR_CSTORE_LOADING) {
		pt_assert(pthread_cond_wait(&entry->state_cond, &entry->state_lock));
	}

	enum fbr_cstore_state state = entry->state;

	pt_assert(pthread_mutex_unlock(&entry->state_lock));

	return state;
}

static void
_cstore_set_state(struct fbr_cstore_entry *entry, enum fbr_cstore_state state)
{
	fbr_cstore_entry_ok(entry);
	assert(state == FBR_CSTORE_NONE || state == FBR_CSTORE_OK);

	pt_assert(pthread_mutex_lock(&entry->state_lock));

	assert(entry->state == FBR_CSTORE_LOADING);
	entry->state = state;

	pt_assert(pthread_cond_broadcast(&entry->state_cond));

	pt_assert(pthread_mutex_unlock(&entry->state_lock));
}

void
fbr_cstore_set_ok(struct fbr_cstore_entry *entry)
{
	_cstore_set_state(entry, FBR_CSTORE_OK);
}

void
fbr_cstore_set_error(struct fbr_cstore_entry *entry)
{
	_cstore_set_state(entry, FBR_CSTORE_NONE);
}

static void
_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry, int prune_lru)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_entry_ok(entry);
	assert(entry->alloc == FBR_CSTORE_ENTRY_USED);

	struct fbr_cstore_head *head = _cstore_get_head(cstore, entry->hash);
	pt_assert(pthread_mutex_lock(&head->lock));
	fbr_cstore_head_ok(head);

	assert(entry->refcount);
	entry->refcount--;

	if (prune_lru && entry->in_lru) {
		_cstore_lru_delete(cstore, head, entry);
	}

	if (entry->refcount) {
		pt_assert(pthread_mutex_unlock(&head->lock));
		return;
	}

	_cstore_entry_free(cstore, head, entry);

	pt_assert(pthread_mutex_unlock(&head->lock));
}

void
fbr_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	_cstore_release(cstore, entry, 0);
}

void
fbr_cstore_remove(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	_cstore_release(cstore, entry, 1);
}

void
fbr_cstore_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	fbr_cstore_async_free(cstore);

	for (size_t i = 0; i < fbr_array_len(cstore->heads); i++) {
		struct fbr_cstore_head *head = &cstore->heads[i];
		fbr_cstore_head_ok(head);

		while (head->slabs) {
			struct fbr_cstore_entry_slab *slab = head->slabs;
			head->slabs = slab->next;

			for (size_t i = 0; i < slab->count; i++) {
				struct fbr_cstore_entry *entry = &slab->entries[i];

				pt_assert(pthread_mutex_destroy(&entry->state_lock));
				pt_assert(pthread_cond_destroy(&entry->state_cond));

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

	int do_free = cstore->do_free;

	fbr_ZERO(cstore);

	if (do_free) {
		free(cstore);
	}
}
