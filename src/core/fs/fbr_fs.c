/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/context/fbr_callback.h"
#include "core/store/fbr_store.h"

/*
 * Each directory has a list of files with references
 * Each directory lives in the dindex and is controlled by the LRU
 * Each directory has a reference to its sibling inode file
 * Each file has a parent inode value
 *
 * The root directory doesnt live in the LRU, the fs owns its ref
 * It also owns its parent inode ref
 * The root inode has a hidden ref
 */

static const struct fbr_store_callbacks _STORE_CALLBACKS_EMPTY;

struct fbr_fs *
fbr_fs_alloc(void)
{
	struct fbr_fs *fs;

	fs = calloc(1, sizeof(*fs));
	assert(fs);

	fs->magic = FBR_FS_MAGIC;

	fbr_inodes_alloc(fs);
	fbr_dindex_alloc(fs);

	assert_dev(fs->inodes);
	assert_dev(fs->dindex);

	pt_assert(pthread_mutex_init(&fs->lock, NULL));

	fs->store = &_STORE_CALLBACKS_EMPTY;
	fs->log = fbr_fs_logger;

	fbr_fs_ok(fs);

	fbr_context_request_init();

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
	fbr_dindex_release_root(fs);

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
	assert_zero(fs->shutdown);

	fs->shutdown = 1;

	fbr_fs_release_all(fs, 1);

	fbr_dindex_free_all(fs);
	fbr_inodes_free_all(fs);

	pt_assert(pthread_mutex_destroy(&fs->lock));

	fbr_ZERO(fs);

	free(fs);

	fbr_context_request_finish();
}
