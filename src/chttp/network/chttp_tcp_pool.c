/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "chttp.h"
#include "chttp_tcp_pool.h"

struct chttp_tcp_pool _TCP_POOL = {
	CHTTP_TCP_POOL_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	RB_INITIALIZER(_TCP_POOL.pool_tree),
	TAILQ_HEAD_INITIALIZER(_TCP_POOL.free_list),
	TAILQ_HEAD_INITIALIZER(_TCP_POOL.lru_list),
	{{0}},
	{0}
};

static int _tcp_pool_cmp(const struct chttp_tcp_pool_entry *k1,
	const struct chttp_tcp_pool_entry *k2);

RB_GENERATE(chttp_tcp_pool_tree, chttp_tcp_pool_entry, tree_entry, _tcp_pool_cmp)

static inline void
_tcp_pool_LOCK(void)
{
	chttp_tcp_pool_ok();
	pt_assert(pthread_mutex_lock(&_TCP_POOL.lock));
}

static inline void
_tcp_pool_UNLOCK(void)
{
	chttp_tcp_pool_ok();
	pt_assert(pthread_mutex_unlock(&_TCP_POOL.lock));
}

static void
_tcp_pool_init(void)
{
	chttp_tcp_pool_ok();
	assert_zero(_TCP_POOL.initialized);

	chttp_load_config();

	assert(RB_EMPTY(&_TCP_POOL.pool_tree));
	assert(TAILQ_EMPTY(&_TCP_POOL.free_list));
	assert(TAILQ_EMPTY(&_TCP_POOL.lru_list));

	size_t pool_size = CHTTP_CONFIG.tcp_pool_size;
	assert(pool_size <= CHTTP_TCP_POOL_SIZE);

	/* Create the free_list */
	for (size_t i = 0; i < pool_size; i++) {
		assert_zero(_TCP_POOL.entries[i].magic);
		TAILQ_INSERT_TAIL(&_TCP_POOL.free_list, &_TCP_POOL.entries[i], list_entry);
	}

	_TCP_POOL.stats.size = pool_size;
	_TCP_POOL.initialized = 1;
}

static int
_tcp_pool_cmp(const struct chttp_tcp_pool_entry *k1, const struct chttp_tcp_pool_entry *k2)
{
	chttp_pool_entry_ok(k1);
	chttp_pool_entry_ok(k2);

	return chttp_addr_cmp(&k1->addr, &k2->addr);
}

static struct chttp_tcp_pool_entry *
_tcp_pool_remove_entry(struct chttp_tcp_pool_entry *entry)
{
	chttp_tcp_pool_ok();
	chttp_pool_entry_ok(entry);

	struct chttp_tcp_pool_entry *head = RB_FIND(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree,
		entry);
	chttp_pool_entry_ok(head);

	if (head == entry) {
		if (!entry->next) {
			// Single head
			assert(RB_REMOVE(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry));
			TAILQ_REMOVE(&_TCP_POOL.lru_list, entry, list_entry);
		} else {
			// Move up the next entry
			struct chttp_tcp_pool_entry *next = entry->next;
			chttp_pool_entry_ok(next);

			TAILQ_INSERT_AFTER(&_TCP_POOL.lru_list, entry, next, list_entry);
			TAILQ_REMOVE(&_TCP_POOL.lru_list, entry, list_entry);

			assert(RB_REMOVE(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry));
			assert_zero(RB_INSERT(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, next));
		}
	} else {
		// Find the entry and cut it out
		int found = 0;
		while (head->next) {
			chttp_pool_entry_ok(head->next);

			if (head->next == entry) {
				head->next = head->next->next;
				found++;
			}
		}
		assert (found == 1);
	}

	if (entry->addr.state == CHTTP_ADDR_CONNECTED) {
		chttp_tcp_close(&entry->addr);
	}

	struct chttp_tcp_pool_entry *next = entry->next;

	chttp_addr_reset(&entry->addr);
	fbr_zero(entry);
	TAILQ_INSERT_TAIL(&_TCP_POOL.free_list, entry, list_entry);

	_TCP_POOL.stats.deleted++;

	return next;
}

int
chttp_tcp_pool_lookup(struct chttp_addr *addr)
{
	chttp_tcp_pool_ok();
	chttp_addr_resolved(addr);

	addr->reused = 0;

	_tcp_pool_LOCK();

	if (!_TCP_POOL.initialized) {
		_tcp_pool_init();
	}
	assert(_TCP_POOL.initialized);

	_TCP_POOL.stats.lookups++;

	struct chttp_tcp_pool_entry find;
	find.magic = CHTTP_TCP_POOL_ENTRY_MAGIC;
	chttp_addr_clone(&find.addr, addr);

	struct chttp_tcp_pool_entry *head = RB_FIND(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree,
		&find);

	if (head) {
		// Move to the front of the LRU
		if (TAILQ_FIRST(&_TCP_POOL.lru_list) != head) {
			TAILQ_REMOVE(&_TCP_POOL.lru_list, head, list_entry);
			TAILQ_INSERT_HEAD(&_TCP_POOL.lru_list, head, list_entry);

			_TCP_POOL.stats.lru++;
		}

		// Find a good connection
		while (head) {
			chttp_pool_entry_ok(head);

			if (head->expiration < fbr_get_time()) {
				head = _tcp_pool_remove_entry(head);
				_TCP_POOL.stats.expired++;

				continue;
			}

			chttp_addr_move(addr, &head->addr);
			_tcp_pool_remove_entry(head);

			addr->reused = 1;

			break;
		}
	}

	_tcp_pool_UNLOCK();

	if (addr->reused) {
		chttp_addr_connected(addr);

		_TCP_POOL.stats.cache_hits++;
	} else {
		chttp_addr_resolved(addr);

		_TCP_POOL.stats.cache_misses++;
	}

	return addr->reused;
}

static struct chttp_tcp_pool_entry *
_tcp_pool_get_entry(void)
{
	chttp_tcp_pool_ok();

	struct chttp_tcp_pool_entry *entry;

	if (!TAILQ_EMPTY(&_TCP_POOL.free_list)) {
		entry = TAILQ_FIRST(&_TCP_POOL.free_list);
		assert(entry);

		TAILQ_REMOVE(&_TCP_POOL.free_list, entry, list_entry);

		assert_zero(entry->magic);
		entry->magic = CHTTP_TCP_POOL_ENTRY_MAGIC;

		return entry;
	} else if (!TAILQ_EMPTY(&_TCP_POOL.lru_list)) {
		// Pull from the LRU
		// The head is oldest, use it and move the next up
		entry = TAILQ_LAST(&_TCP_POOL.lru_list, chttp_tcp_pool_list);
		chttp_pool_entry_ok(entry);

		_tcp_pool_remove_entry(entry);

		assert_zero(TAILQ_EMPTY(&_TCP_POOL.free_list));
		TAILQ_REMOVE(&_TCP_POOL.free_list, entry, list_entry);

		fbr_zero(entry);
		entry->magic = CHTTP_TCP_POOL_ENTRY_MAGIC;

		_TCP_POOL.stats.nuked++;

		return entry;
	}

	return NULL;
}

void
chttp_tcp_pool_store(struct chttp_addr *addr)
{
	chttp_tcp_pool_ok();
	chttp_addr_connected(addr);
	assert(addr->resolved);
	assert_zero(addr->listen);

	_tcp_pool_LOCK();

	if (!_TCP_POOL.initialized) {
		_tcp_pool_init();
	}
	assert(_TCP_POOL.initialized);

	long pool_age_msec = CHTTP_CONFIG.tcp_pool_age_msec;
	double pool_age = (double)pool_age_msec / 1000;

	if (pool_age <= 0) {
		chttp_tcp_close(addr);
		_tcp_pool_UNLOCK();
		return;
	}

	struct chttp_tcp_pool_entry *entry = _tcp_pool_get_entry();
	if (!entry) {
		chttp_tcp_close(addr);
		_TCP_POOL.stats.err_alloc++;
		_tcp_pool_UNLOCK();
		return;
	}

	chttp_pool_entry_ok(entry);
	chttp_addr_move(&entry->addr, addr);
	chttp_addr_connected(&entry->addr);

	double now = fbr_get_time();
	entry->expiration = now + pool_age;

	struct chttp_tcp_pool_entry *head = RB_INSERT(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree,
		entry);

	// Prune expired connections
	if (head) {
		while (head && head->expiration < now) {
			chttp_pool_entry_ok(head);
			head = _tcp_pool_remove_entry(head);
			_TCP_POOL.stats.expired++;
		}

		if (!head) {
			assert_zero(RB_INSERT(chttp_tcp_pool_tree, &_TCP_POOL.pool_tree, entry));
			TAILQ_INSERT_HEAD(&_TCP_POOL.lru_list, entry, list_entry);
		} else {
			chttp_pool_entry_ok(head);

			// Add entry to the back
			while (head->next) {
				chttp_pool_entry_ok(head->next);

				if (head->next->expiration < now) {
					_tcp_pool_remove_entry(head->next);
					_TCP_POOL.stats.expired++;

					continue;
				}

				head = head->next;
			}

			head->next = entry;
		}
	} else {
		TAILQ_INSERT_HEAD(&_TCP_POOL.lru_list, entry, list_entry);
	}

	_TCP_POOL.stats.insertions++;

	_tcp_pool_UNLOCK();

	chttp_addr_resolved(addr);
}

void
chttp_tcp_pool_close(void)
{
	_tcp_pool_LOCK();

	if (!_TCP_POOL.initialized) {
		_tcp_pool_UNLOCK();
		return;
	}

	struct chttp_tcp_pool_entry *entry, *temp;

	TAILQ_FOREACH_SAFE(entry, &_TCP_POOL.lru_list, list_entry, temp) {
		while (entry) {
			chttp_pool_entry_ok(entry);
			entry = _tcp_pool_remove_entry(entry);
		}
	}

	assert(RB_EMPTY(&_TCP_POOL.pool_tree));
	assert(TAILQ_EMPTY(&_TCP_POOL.lru_list));

	size_t size = 0;
	TAILQ_FOREACH(entry, &_TCP_POOL.free_list, list_entry) {
		fbr_object_empty(entry);
		size++;
	}

	fbr_ASSERT(size == _TCP_POOL.stats.size, "_TCP_POOL size fail, got %zu, expected %zu",
		size, _TCP_POOL.stats.size);

	_TCP_POOL.initialized = 0;

	_tcp_pool_UNLOCK();
}
