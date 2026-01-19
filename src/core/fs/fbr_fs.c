/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "compress/fbr_gzip.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"

static const struct fbr_store_callbacks _STORE_CALLBACKS_EMPTY;

static void
_fs_config_init(struct fbr_fs *fs)
{
	assert_dev(fs);

	if (fbr_gzip_enabled()) {
		fs->config.gzip_index = 1;
	}

	fs->config.flush_attempts = 100;
	fs->config.flush_timeout_sec = 60;
}

struct fbr_fs *
fbr_fs_alloc(void)
{
	struct fbr_fs *fs;

	fs = calloc(1, sizeof(*fs));
	assert(fs);

	fs->magic = FBR_FS_MAGIC;

	fbr_context_request_init();
	fbr_inodes_alloc(fs);
	fbr_dindex_alloc(fs);

	assert_dev(fs->inodes);
	assert_dev(fs->dindex);

	pt_assert(pthread_mutex_init(&fs->lock, NULL));

	fs->store = &_STORE_CALLBACKS_EMPTY;

	_fs_config_init(fs);

	fbr_fs_ok(fs);

	return fs;
}

void
fbr_fs_LOCK(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	pt_assert(pthread_mutex_lock(&fs->lock));
}

void
fbr_fs_UNLOCK(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	pt_assert(pthread_mutex_unlock(&fs->lock));
}

void
fbr_fs_release_all(struct fbr_fs *fs, int release_root_inode)
{
	fbr_fs_ok(fs);

	fbr_dindex_lru_purge(fs, 0);

	if (release_root_inode) {
		fbr_fs_LOCK(fs);

		if (fs->root_file) {
			fbr_inode_release(fs, &fs->root_file);
		}
		assert_zero_dev(fs->root_file);

		fbr_fs_UNLOCK(fs);
	}
}

void
fbr_fs_set_store(struct fbr_fs *fs, const struct fbr_store_callbacks *store)
{
	fbr_fs_ok(fs);
	assert(fs->store == &_STORE_CALLBACKS_EMPTY);
	assert(store);

	fs->store = store;
}

void
fbr_fs_free(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	fs->shutdown = 1;

	if (fs->root_file) {
		fbr_inode_release(fs, &fs->root_file);
	}

	fbr_context_request_finish();
	fbr_dindex_free_all(fs);
	fbr_inodes_free_all(fs);

	pt_assert(pthread_mutex_destroy(&fs->lock));

	fbr_zero(fs);
	free(fs);
}
