/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "chttp.h"
#include "chttp_dns.h"
#include "chttp_dns_cache.h"

struct chttp_dns_cache _DNS_CACHE = {
	CHTTP_DNS_CACHE_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	0,
	RB_INITIALIZER(_DNS_CACHE.cache_tree),
	TAILQ_HEAD_INITIALIZER(_DNS_CACHE.free_list),
	TAILQ_HEAD_INITIALIZER(_DNS_CACHE.lru_list),
	{{0}},
	{0}
};

static int _dns_cache_cmp(const struct chttp_dns_cache_entry *k1,
	const struct chttp_dns_cache_entry *k2);

RB_GENERATE(chttp_dns_cache_tree, chttp_dns_cache_entry, tree_entry, _dns_cache_cmp)

static inline void
_dns_cache_LOCK(void)
{
	chttp_dns_cache_ok();
	pt_assert(pthread_mutex_lock(&_DNS_CACHE.lock));
}

static inline void
_dns_cache_UNLOCK(void)
{
	chttp_dns_cache_ok();
	pt_assert(pthread_mutex_unlock(&_DNS_CACHE.lock));
}

static void
_dns_cache_init(void)
{
	chttp_dns_cache_ok();
	assert_zero(_DNS_CACHE.initialized);

	chttp_load_config();
	assert_dev(CHTTP_CONFIG.init);

	assert(RB_EMPTY(&_DNS_CACHE.cache_tree));
	assert(TAILQ_EMPTY(&_DNS_CACHE.free_list));
	assert(TAILQ_EMPTY(&_DNS_CACHE.lru_list));

	size_t cache_size = CHTTP_CONFIG.dns_cache_size;
	assert(cache_size <= CHTTP_DNS_CACHE_SIZE);

	/* Create the free_list */
	for (size_t i = 0; i < cache_size; i++) {
		assert_zero(_DNS_CACHE.entries[i].magic);
		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, &_DNS_CACHE.entries[i], list_entry);
	}

	_DNS_CACHE.stats.size = cache_size;
	_DNS_CACHE.initialized = 1;
}

static int
_dns_cache_cmp(const struct chttp_dns_cache_entry *k1, const struct chttp_dns_cache_entry *k2)
{
	chttp_dns_entry_ok(k1);
	chttp_dns_entry_ok(k2);

	return strcmp(k1->hostname, k2->hostname);
}

int
chttp_dns_cache_lookup(const char *host, size_t host_len, struct chttp_addr *addr_dest, int port,
    unsigned int flags)
{
	chttp_dns_cache_ok();
	assert(host);
	assert(host_len);
	assert(addr_dest);

	if (host_len >= CHTTP_DNS_CACHE_HOST_MAX) {
		fbr_atomic_add(&_DNS_CACHE.stats.err_too_long, 1);
		return 0;
	}

	_dns_cache_LOCK();

	if (!_DNS_CACHE.initialized) {
		_dns_cache_init();
	}
	assert(_DNS_CACHE.initialized);

	long cache_ttl = CHTTP_CONFIG.dns_cache_ttl;

	if (cache_ttl <= 0) {
		_dns_cache_UNLOCK();
		return 0;
	}

	_DNS_CACHE.stats.lookups++;

	struct chttp_dns_cache_entry find;
	find.magic = CHTTP_DNS_CACHE_ENTRY_MAGIC;
	strncpy(find.hostname, host, host_len + 1);

	struct chttp_dns_cache_entry *dns_head = RB_FIND(chttp_dns_cache_tree,
		&_DNS_CACHE.cache_tree, &find);
	if (!dns_head) {
		_dns_cache_UNLOCK();
		return 0;
	}

	chttp_dns_entry_ok(dns_head);

	struct chttp_dns_cache_entry *dns_entry = dns_head;
	size_t pos = 0;

	// Calculate next for RR
	if (!(flags & DNS_DISABLE_RR)) {
		pos = (dns_head->current + 1) % dns_head->length;
		dns_head->current = pos;
	}

	while (pos > 0) {
		dns_entry = dns_entry->next;
		chttp_dns_entry_ok(dns_entry);

		pos--;
	}

	assert(dns_entry->state == CHTTP_DNS_CACHE_OK ||
		dns_entry->state == CHTTP_DNS_CACHE_STALE);

	// Move to the front of the LRU
	if (TAILQ_FIRST(&_DNS_CACHE.lru_list) != dns_head) {
		TAILQ_REMOVE(&_DNS_CACHE.lru_list, dns_head, list_entry);
		TAILQ_INSERT_HEAD(&_DNS_CACHE.lru_list, dns_head, list_entry);

		_DNS_CACHE.stats.lru++;
	}

	double now = fbr_get_time();
	assert(dns_head->expiration);

	if (dns_head->expiration < now) {
		// Expired, mark as stale and add more time
		// Force this client to do a fresh lookup
		dns_head->state = CHTTP_DNS_CACHE_STALE;
		dns_head->expiration = now + 10;

		_DNS_CACHE.stats.expired++;

		_dns_cache_UNLOCK();

		return 0;
	}

	chttp_dns_copy(addr_dest, &dns_entry->addr.sa, port);
	chttp_addr_resolved(addr_dest);

	_DNS_CACHE.stats.cache_hits++;

	_dns_cache_UNLOCK();

	return 1;
}

static void
_dns_free_entry(struct chttp_dns_cache_entry *dns_head)
{
	chttp_dns_cache_ok();

	struct chttp_dns_cache_entry *dns_entry = dns_head;

	while (dns_entry) {
		chttp_dns_entry_ok(dns_entry);

		struct chttp_dns_cache_entry *dns_temp = dns_entry;
		dns_entry = dns_entry->next;

		chttp_addr_reset(&dns_temp->addr);
		fbr_zero(dns_temp);

		TAILQ_INSERT_TAIL(&_DNS_CACHE.free_list, dns_temp, list_entry);
	}
}

static void
_dns_remove_entry(struct chttp_dns_cache_entry *dns_entry)
{
	chttp_dns_cache_ok();
	chttp_dns_entry_ok(dns_entry);

	assert(RB_REMOVE(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_entry));
	TAILQ_REMOVE(&_DNS_CACHE.lru_list, dns_entry, list_entry);

	_dns_free_entry(dns_entry);
}

static struct chttp_dns_cache_entry *
_dns_get_entry(void)
{
	chttp_dns_cache_ok();

	struct chttp_dns_cache_entry *entry;

	if (!TAILQ_EMPTY(&_DNS_CACHE.free_list)) {
		entry = TAILQ_FIRST(&_DNS_CACHE.free_list);
		assert(entry);

		TAILQ_REMOVE(&_DNS_CACHE.free_list, entry, list_entry);

		return entry;
	} else if (!TAILQ_EMPTY(&_DNS_CACHE.lru_list)) {
		// Pull from the LRU
		entry = TAILQ_LAST(&_DNS_CACHE.lru_list, chttp_dns_cache_list);
		chttp_dns_entry_ok(entry);

		_dns_remove_entry(entry);

		_DNS_CACHE.stats.nuked++;

		assert(!TAILQ_EMPTY(&_DNS_CACHE.free_list));

		return _dns_get_entry();
	}

	return NULL;
}

void
chttp_dns_cache_store(const char *host, size_t host_len, struct addrinfo *ai_list)
{
	chttp_dns_cache_ok();
	assert(_DNS_CACHE.initialized);
	assert(host);
	assert(host_len);
	assert(ai_list);

	if (host_len >= CHTTP_DNS_CACHE_HOST_MAX) {
		fbr_atomic_add(&_DNS_CACHE.stats.err_too_long, 1);
		return;
	}

	_dns_cache_LOCK();

	if (!_DNS_CACHE.initialized) {
		_dns_cache_init();
	}
	assert(_DNS_CACHE.initialized);

	long cache_ttl = CHTTP_CONFIG.dns_cache_ttl;
	if (cache_ttl <= 0) {
		_dns_cache_UNLOCK();
		return;
	}

	struct addrinfo *ai_entry;
	struct chttp_dns_cache_entry *dns_head = NULL;
	struct chttp_dns_cache_entry *dns_last = NULL;
	struct chttp_dns_cache_entry *dns_entry;
	size_t count = 0;

	for (ai_entry = ai_list; ai_entry; ai_entry = ai_entry->ai_next) {
		dns_entry = _dns_get_entry();
		if (!dns_entry) {
			_dns_free_entry(dns_head);
			_DNS_CACHE.stats.err_alloc++;
			_dns_cache_UNLOCK();
			return;
		}

		if (!dns_head) {
			dns_head = dns_entry;
		} else {
			assert(dns_last);
			dns_last->next = dns_entry;
		}

		fbr_zero(dns_entry);
		dns_entry->magic = CHTTP_DNS_CACHE_ENTRY_MAGIC;

		chttp_dns_copy(&dns_entry->addr, ai_entry->ai_addr, 0);
		chttp_addr_resolved(&dns_entry->addr);

		dns_entry->state = CHTTP_DNS_CACHE_OK;

		count++;
		_DNS_CACHE.stats.insertions++;

		dns_last = dns_entry;
	}

	assert(dns_head);

	dns_head->length = count;
	dns_head->expiration = fbr_get_time() + cache_ttl;
	strncpy(dns_head->hostname, host, host_len + 1);

	TAILQ_INSERT_HEAD(&_DNS_CACHE.lru_list, dns_head, list_entry);
	dns_entry = RB_INSERT(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_head);

	if (dns_entry) {
		chttp_dns_entry_ok(dns_entry);
		chttp_addr_ok(&dns_entry->addr);

		if (dns_entry->state == CHTTP_DNS_CACHE_OK) {
			_DNS_CACHE.stats.dups++;
		}

		_dns_remove_entry(dns_entry);

		assert_zero(RB_INSERT(chttp_dns_cache_tree, &_DNS_CACHE.cache_tree, dns_head));
	}

	_dns_cache_UNLOCK();
}
