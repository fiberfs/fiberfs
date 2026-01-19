/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <signal.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "data/queue.h"

struct {
	unsigned int				magic;
#define _REQUEST_POOL_MAGIC			0x119D1944

	pthread_mutex_t				lock;

	TAILQ_HEAD(, fbr_request)		free_list;
	TAILQ_HEAD(, fbr_request)		active_list;

	size_t					free_size;
	size_t					active_size;
} __REQUEST_POOL = {
	_REQUEST_POOL_MAGIC,
	PTHREAD_MUTEX_INITIALIZER,
	TAILQ_HEAD_INITIALIZER(__REQUEST_POOL.free_list),
	TAILQ_HEAD_INITIALIZER(__REQUEST_POOL.active_list),
	0, 0
}, *_REQUEST_POOL = &__REQUEST_POOL;

static unsigned int _REQUEST_KEY_COUNT;
static pthread_key_t _REQUEST_KEY;

static unsigned long _REQUEST_ID_THREAD_COUNT = FBR_REQUEST_ID_THREAD_MIN;
static unsigned long _REQUEST_ID_COUNT  = FBR_REQUEST_ID_MIN;

unsigned long
fbr_request_id_gen(void)
{
	unsigned long id = fbr_atomic_add(&_REQUEST_ID_COUNT, 1);

	if (id < FBR_REQUEST_ID_MIN) {
		id += UINT32_MAX;
	}

	return id;
}

unsigned long
fbr_request_id_thread_gen(void)
{
	unsigned long id = fbr_atomic_add(&_REQUEST_ID_THREAD_COUNT, 1);
	assert(id < FBR_REQUEST_ID_MIN);

	return id;
}

void
fbr_context_request_init(void)
{
	unsigned int key_count = fbr_atomic_add(&_REQUEST_KEY_COUNT, 1);
	assert(key_count);

	if (key_count > 1) {
		return;
	}

	pt_assert(pthread_key_create(&_REQUEST_KEY, NULL));
}

void
fbr_context_request_finish(void)
{
	assert(_REQUEST_KEY_COUNT);
	unsigned int key_count = fbr_atomic_sub(&_REQUEST_KEY_COUNT, 1);

	if (key_count) {
		return;
	}

	pt_assert(pthread_key_delete(_REQUEST_KEY));
}

static void
_request_init(struct fbr_request *request, fuse_req_t fuse_req, const char *name)
{
	assert_dev(request);

	request->fuse_req = fuse_req;
	pt_assert(pthread_setspecific(_REQUEST_KEY, request));

	request->name = name;
	request->time_start = fbr_get_time();
	request->id = fbr_request_id_gen();
	request->thread = pthread_self();

	if (!request->fuse_ctx) {
		request->fuse_ctx = fbr_fuse_get_context();
	} else {
		fbr_fuse_context_ok(request->fuse_ctx);
	}

	fbr_workspace_ok(request->workspace);
	assert_dev(request->workspace->free >= FBR_WORKSPACE_MIN_SIZE);
	assert_zero_dev(request->workspace->pos);

	fbr_rlog_workspace_alloc(request);
}

static struct fbr_request *
_request_pool_get(fuse_req_t fuse_req, const char *name)
{
	fbr_magic_check(_REQUEST_POOL, _REQUEST_POOL_MAGIC);
	assert_dev(name);
	assert_dev(_REQUEST_KEY_COUNT);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	if (TAILQ_EMPTY(&_REQUEST_POOL->free_list)) {
		assert_zero_dev(_REQUEST_POOL->free_size);
		pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
		return NULL;
	}

	assert_dev(_REQUEST_POOL->free_size);

	struct fbr_request *request = TAILQ_FIRST(&_REQUEST_POOL->free_list);
	fbr_request_ok(request);
	assert_zero_dev(request->fuse_req);

	_request_init(request, fuse_req, name);

	TAILQ_REMOVE(&_REQUEST_POOL->free_list, request, entry);
	_REQUEST_POOL->free_size--;

	TAILQ_INSERT_TAIL(&_REQUEST_POOL->active_list, request, entry);
	_REQUEST_POOL->active_size++;

	assert_dev(request->fuse_ctx);
	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_add(&fs->stats.requests_recycled);
	fbr_fs_stat_add(&fs->stats.requests_active);
	fbr_fs_stat_sub(&fs->stats.requests_pooled);

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));

	return request;
}

static void
_request_pool_active(struct fbr_request *request)
{
	fbr_magic_check(_REQUEST_POOL, _REQUEST_POOL_MAGIC);
	fbr_request_ok(request);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	TAILQ_INSERT_TAIL(&_REQUEST_POOL->active_list, request, entry);
	_REQUEST_POOL->active_size++;

	assert_dev(request->fuse_ctx);
	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_add(&fs->stats.requests_alloc);
	fbr_fs_stat_add(&fs->stats.requests_active);

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
}

struct fbr_request *
fbr_request_alloc(fuse_req_t fuse_req, const char *name)
{
	assert(_REQUEST_KEY_COUNT);
	assert_zero_dev(fbr_request_get());

	struct fbr_request *request = _request_pool_get(fuse_req, name);
	if (request) {
		return request;
	}

	size_t workspace_size = fbr_workspace_size();

	request = calloc(1, sizeof(*request) + workspace_size);
	assert(request);

	request->magic = FBR_REQUEST_MAGIC;
	request->workspace = fbr_workspace_init(request + 1, workspace_size);

	_request_init(request, fuse_req, name);
	_request_pool_active(request);

	return request;
}

struct fbr_request *
fbr_request_get(void)
{
	if (!_REQUEST_KEY_COUNT) {
		return NULL;
	}

	struct fbr_request *request = pthread_getspecific(_REQUEST_KEY);
	if (!request) {
		return NULL;
	}

	fbr_request_ok(request);

	return request;
}

fuse_req_t
fbr_request_take_fuse(struct fbr_request *request)
{
	fbr_request_ok(request);

	fuse_req_t fuse_req = request->fuse_req;
	if (fuse_req) {
		fuse_req_t ret = fbr_compare_swap(&request->fuse_req, fuse_req, NULL);

		if (ret == fuse_req) {
			return fuse_req;
		}

		assert_zero_dev(ret);
	}

	assert_zero_dev(request->fuse_req);

	return NULL;
}

static void
_request_free(struct fbr_request *request)
{
	assert_dev(request);

	fbr_workspace_free(request->workspace);

	fbr_zero(request);
	free(request);
}

static void
_request_pool_put(struct fbr_request *request)
{
	fbr_magic_check(_REQUEST_POOL, _REQUEST_POOL_MAGIC);
	assert_dev(request);
	assert_dev(request->fuse_ctx);

	struct fbr_fs *fs = request->fuse_ctx->fs;
	assert_dev(fs);

	pt_assert(pthread_mutex_lock(&_REQUEST_POOL->lock));

	assert(_REQUEST_POOL->active_size);

	TAILQ_REMOVE(&_REQUEST_POOL->active_list, request, entry);
	_REQUEST_POOL->active_size--;

	if (_REQUEST_POOL->free_size >= FBR_REQUEST_POOL_MAX_SIZE) {
		fbr_fs_stat_add(&fs->stats.requests_freed);
		pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
		_request_free(request);
		return;
	}

	TAILQ_INSERT_TAIL(&_REQUEST_POOL->free_list, request, entry);
	_REQUEST_POOL->free_size++;

	fbr_fs_stat_add(&fs->stats.requests_pooled);

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
}

void
fbr_request_free(struct fbr_request *request)
{
	fbr_request_ok(request);
	fbr_fuse_context_ok(request->fuse_ctx);
	assert_zero(request->fuse_req);
	assert(_REQUEST_KEY_COUNT);

	assert_dev(fbr_request_get() == request);
	pt_assert(pthread_setspecific(_REQUEST_KEY, NULL));
	assert_zero_dev(fbr_request_get());

	struct fbr_fs *fs = request->fuse_ctx->fs;
	fbr_fs_ok(fs);

	fbr_fs_stat_sub(&fs->stats.requests_active);

	request->not_fuse = 0;
	request->id = 0;
	request->name = NULL;
	request->time_start = 0;

	fbr_zero(&request->thread);

	fbr_rlog_free(&request->rlog);
	fbr_workspace_reset(request->workspace);

	_request_pool_put(request);
}

void
fbr_request_pool_shutdown(struct fbr_fs *fs)
{
	fbr_magic_check(_REQUEST_POOL, _REQUEST_POOL_MAGIC);
	fbr_fs_ok(fs);

	int max_ms = 500;
	int wait_ms = 0;
	int sleep_ms = 25;
	while (wait_ms < max_ms && !TAILQ_EMPTY(&_REQUEST_POOL->active_list)) {
		if (fs->fuse_ctx) {
			fbr_fuse_context_ok(fs->fuse_ctx);
			if (fs->fuse_ctx->error) {
				break;
			}
		}

		fbr_sleep_ms(sleep_ms);
		wait_ms += sleep_ms;
	}

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

	if (!TAILQ_EMPTY(&_REQUEST_POOL->active_list)) {
		if (fs->fuse_ctx) {
			fbr_fuse_context_ok(fs->fuse_ctx);
			fs->fuse_ctx->error = 1;
		}
	}

	TAILQ_FOREACH_SAFE(request, &_REQUEST_POOL->active_list, entry, temp) {
		fbr_request_ok(request);

		fuse_req_t fuse_req = fbr_request_take_fuse(request);

		fbr_rlog(FBR_LOG_REQUEST, "active id: %lu name: %s running: %s", request->id,
			request->name, fuse_req ? "YES" : "NO");

		if (fuse_req) {
			fbr_rlog(FBR_LOG_REQUEST, "id: %lu sending EIO", request->id);
			fuse_reply_err(fuse_req, EIO);
		}

		assert_zero_dev(request->fuse_req);

		if (request->thread) {
			fbr_rlog(FBR_LOG_REQUEST, "id: %lu sending SIGQUIT", request->id);
			pthread_kill(request->thread, SIGQUIT);
			fbr_zero(&request->thread);
		}
	}

	pt_assert(pthread_mutex_unlock(&_REQUEST_POOL->lock));
}
