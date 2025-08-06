/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cache_store.h"

struct fbr_cache_store __CSTORE;
struct fbr_cache_store *_CSTORE = &__CSTORE;

#define _cstore_ok()	fbr_cstore_ok(_CSTORE)

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
		pt_assert(pthread_rwlock_init(&head->lock, NULL));

		fbr_cstore_head_ok(head);
	}

	TAILQ_INIT(&_CSTORE->lru);
	pt_assert(pthread_mutex_init(&_CSTORE->lru_lock, NULL));

	_cstore_ok();
}

void
fbr_cache_store_free(void)
{
	_cstore_ok();

	for (size_t i = 0; i < fbr_array_len(_CSTORE->heads); i++) {
		struct fbr_cstore_head *head = &_CSTORE->heads[i];
		fbr_cstore_head_ok(head);

		pt_assert(pthread_rwlock_destroy(&head->lock));
		fbr_ZERO(head);
	}

	pt_assert(pthread_mutex_destroy(&_CSTORE->lru_lock));

	fbr_ZERO(_CSTORE);
}
