/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <time.h>

#include "fiberfs.h"
#include "core/fuse/fbr_fuse.h"

void
fbr_fuse_LOCK(struct fbr_fuse_context *fuse_ctx, pthread_mutex_t *lock)
{
	assert(lock);

	if (!fuse_ctx) {
		pt_assert(pthread_mutex_lock(lock));
		return;
	}

	int ret;

	do {
		fbr_fuse_mounted(fuse_ctx);

		struct timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = 1000 * 1000 * 250;
		fbr_timespec_add_clock(&ts);

		ret = pthread_mutex_timedlock(lock, &ts);
	} while (ret == ETIMEDOUT);

	pt_assert(ret);
}
