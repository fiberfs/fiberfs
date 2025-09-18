/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "core/request/fbr_request.h"

static void *_cstore_load_thread(void *arg);

void
fbr_cstore_loader_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_loader *loader = &cstore->loader;

	fbr_ZERO(loader);
	loader->state = FBR_CSTORE_LOADER_READING;
	loader->thread_count = _CSTORE_CONFIG.loader_threads;

	if (!loader->thread_count) {
		return;
	} else if (loader->thread_count > FBR_CSTORE_LOAD_THREAD_MAX) {
		loader->thread_count = FBR_CSTORE_LOAD_THREAD_MAX;
	}
	while (256 % loader->thread_count) {
		loader->thread_count--;
	}

	for (size_t i = 0; i < loader->thread_count; i++) {
		pt_assert(pthread_create(&loader->threads[i], NULL, _cstore_load_thread,
			cstore));
	}
}

static void *
_cstore_load_thread(void *arg)
{
	assert(arg);

	struct fbr_cstore *cstore = arg;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_loader *loader = &cstore->loader;
	size_t pos = fbr_atomic_add(&loader->thread_pos, 1);
	size_t thread_id = fbr_request_id_thread_gen();

	fbr_log_print(cstore->log, FBR_LOG_CS_LOADER, thread_id, "thread %zu running", pos);

	while (!loader->stop) {
		fbr_sleep_ms(100);
	}

	size_t count = fbr_atomic_add(&loader->thread_done, 1);
	if (count == loader->thread_count) {
		assert_dev(loader->state == FBR_CSTORE_LOADER_READING);
		loader->state = FBR_CSTORE_LOADER_DONE;
	}

	return NULL;
}

void
fbr_cstore_loader_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_loader *loader = &cstore->loader;

	loader->stop = 1;

	for (size_t i = 0; i < loader->thread_count; i++) {
		pt_assert(pthread_join(loader->threads[i], NULL));
	}

	assert(loader->thread_pos == loader->thread_count);
	assert_dev(loader->thread_done == loader->thread_count);
	assert_dev(!loader->thread_count || loader->state == FBR_CSTORE_LOADER_DONE);

	fbr_ZERO(loader);
}
