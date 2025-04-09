/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "data/queue.h"

#define FBR_REQUEST_POOL_MAX_SIZE		64

struct {
	unsigned int				magic;
#define _REQUEST_POOL_MAGIC			0x119D1944

	pthread_mutex_t				lock;

	TAILQ_HEAD(, fbr_request)		free_list;
	TAILQ_HEAD(, fbr_request)		active_list;

	size_t					free_size;
	size_t					active_size;
	unsigned long				id_count;
} __REQUEST_POOL = {
	_REQUEST_POOL_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	TAILQ_HEAD_INITIALIZER(__REQUEST_POOL.free_list),
	TAILQ_HEAD_INITIALIZER(__REQUEST_POOL.active_list),
	0,
	0,
	0
}, *_REQUEST_POOL = &__REQUEST_POOL;

static int _REQUEST_KEY_INIT;
static pthread_key_t _REQUEST_KEY;

struct fbr_request *
_request_pool_get(void)
{
	fbr_magic_check(_REQUEST_POOL, _REQUEST_POOL_MAGIC);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	if (TAILQ_EMPTY(&_REQUEST_POOL->free_list)) {
		assert_zero_dev(_REQUEST_POOL->free_size);
		pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
		return NULL;
	}

	assert_dev(_REQUEST_POOL->free_size);

	struct fbr_request *request = TAILQ_FIRST(&_REQUEST_POOL->free_list);
	fbr_request_ok(request);

	TAILQ_REMOVE(&_REQUEST_POOL->free_list, request, entry);
	_REQUEST_POOL->free_size--;

	TAILQ_INSERT_TAIL(&_REQUEST_POOL->active_list, request, entry);
	_REQUEST_POOL->active_size++;

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));

	fbr_fuse_context_ok(request->fuse_ctx);
	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_add(&fs->stats.requests_recycled);
	fbr_fs_stat_add(&fs->stats.requests_active);
	fbr_fs_stat_sub(&fs->stats.requests_pooled);

	return request;
}

void
_request_pool_active(struct fbr_request *request)
{
	fbr_request_ok(request);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	TAILQ_INSERT_TAIL(&_REQUEST_POOL->active_list, request, entry);
	_REQUEST_POOL->active_size++;

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));

	fbr_fuse_context_ok(request->fuse_ctx);
	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_add(&fs->stats.requests_alloc);
	fbr_fs_stat_add(&fs->stats.requests_active);
}

void
fbr_context_request_init(void)
{
	pt_assert(pthread_key_create(&_REQUEST_KEY, NULL));

	_REQUEST_KEY_INIT = 1;
}

void
fbr_context_request_finish(void)
{
	pt_assert(pthread_key_delete(_REQUEST_KEY));

	_REQUEST_KEY_INIT = 0;
}

struct fbr_request *
fbr_request_alloc(fuse_req_t fuse_req)
{
	assert(fuse_req);
	assert(_REQUEST_KEY_INIT);

	struct fbr_request *request = _request_pool_get();

	if (!request) {
		request = calloc(1, sizeof(*request));
		assert(request);

		request->magic = FBR_REQUEST_MAGIC;
		request->simple_id = fbr_atomic_add(&_REQUEST_POOL->id_count, 1);
		request->fuse_ctx = fbr_fuse_callback_ctx();

		_request_pool_active(request);
	}

	fbr_request_ok(request);

	request->fuse_req = fuse_req;
	request->id = fbr_id_gen();

	pt_assert(pthread_setspecific(_REQUEST_KEY, request));

	return request;
}

struct fbr_request *
fbr_request_get(void)
{
	struct fbr_request *request = pthread_getspecific(_REQUEST_KEY);

	if (!request || !_REQUEST_KEY_INIT) {
		return NULL;
	}

	fbr_request_ok(request);

	return request;
}

void
_request_free(struct fbr_request *request)
{
	assert_dev(request);
	fbr_ZERO(request);
	free(request);
}

void
_request_pool_put(struct fbr_request *request)
{
	assert_dev(request);
	assert_dev(request->fuse_ctx);

	struct fbr_fs *fs = request->fuse_ctx->fs;
	assert_dev(fs);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	assert(_REQUEST_POOL->active_size);

	TAILQ_REMOVE(&_REQUEST_POOL->active_list, request, entry);
	_REQUEST_POOL->active_size--;

	if (_REQUEST_POOL->free_size >= FBR_REQUEST_POOL_MAX_SIZE) {
		pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
		_request_free(request);
		fbr_fs_stat_add(&fs->stats.requests_freed);
		return;
	}

	TAILQ_INSERT_TAIL(&_REQUEST_POOL->free_list, request, entry);
	_REQUEST_POOL->free_size++;

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));

	fbr_fs_stat_add(&fs->stats.requests_pooled);
}

void
fbr_request_free(struct fbr_request *request)
{
	fbr_request_ok(request);
	fbr_fuse_context_ok(request->fuse_ctx);
	assert_zero(request->fuse_req);

	request->id = 0;

	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_sub(&fs->stats.requests_active);

	if (fbr_assert_is_dev()) {
		struct fbr_request *sreq = fbr_request_get();
		assert(sreq == request);
	}

	pt_assert(pthread_setspecific(_REQUEST_KEY, NULL));
	assert_zero_dev(fbr_request_get());

	_request_pool_put(request);
}

void
fbr_request_pool_free(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	struct fbr_request *request, *temp;

	TAILQ_FOREACH_SAFE(request, &_REQUEST_POOL->free_list, entry, temp) {
		fbr_request_ok(request);

		TAILQ_REMOVE(&_REQUEST_POOL->free_list, request, entry);
		_REQUEST_POOL->free_size--;

		_request_free(request);

		fbr_fs_stat_sub(&fs->stats.requests_pooled);
		fbr_fs_stat_add(&fs->stats.requests_freed);
	}

	assert_zero(_REQUEST_POOL->free_size);
	assert(TAILQ_EMPTY(&_REQUEST_POOL->free_list));
	assert_zero_dev(fs->stats.requests_pooled);

	TAILQ_FOREACH_SAFE(request, &_REQUEST_POOL->active_list, entry, temp) {
		fbr_request_ok(request);

		fs->log("REQUEST active id: %u (%lu) reply: %s",
			request->simple_id, request->id,
			request->fuse_req ? "NO" : "YES");

		if (request->fuse_req) {
			fuse_reply_err(request->fuse_req, EIO);
			request->fuse_req = NULL;
		}

		TAILQ_REMOVE(&_REQUEST_POOL->active_list, request, entry);
		_REQUEST_POOL->active_size--;

		_request_free(request);

		fbr_fs_stat_sub(&fs->stats.requests_active);
		fbr_fs_stat_add(&fs->stats.requests_freed);
	}

	assert_zero(_REQUEST_POOL->active_size);
	assert(TAILQ_EMPTY(&_REQUEST_POOL->active_list));
	assert_zero_dev(fs->stats.requests_active);
	assert_dev(fs->stats.requests_alloc == fs->stats.requests_freed);

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
}
