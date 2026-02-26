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
#include "config/fbr_config.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"

static const struct fbr_store_callbacks _STORE_CALLBACKS_EMPTY;

void
fbr_fs_config_load(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_config_reader *reader = &fs->config.reader;
	fbr_config_reader_ok(reader);

	int locked = fbr_config_reader_lock(reader);
	if (!locked) {
		assert_dev(reader->init);
		return;
	}

	if (fbr_gzip_enabled()) {
		const char *gzip_index = fbr_conf_get("FS_GZIP_INDEX", "1");
		if (fbr_is_true(gzip_index)) {
			fs->config.gzip_index = 1;
		} else {
			fs->config.gzip_index = 0;
		}
	}

	long dentry_ttl_msec = fbr_conf_get_long("FS_DENTRY_TTL_MSEC", 0);
	if (dentry_ttl_msec > 0) {
		fs->config.dentry_ttl = (double)dentry_ttl_msec / 1000;
	} else {
		fs->config.dentry_ttl = 0;
	}

	fs->config.flush_attempts = fbr_conf_get_ulong("FS_FLUSH_ATTEMPTS", 100);
	fs->config.flush_timeout_sec = fbr_conf_get_ulong("FS_FLUSH_TIMEOUT_SEC", 60);
	fs->config.rlog_size = fbr_conf_get_ulong("LOG_BUFFER_SIZE", FBR_RLOG_MIN_SIZE);
	fs->config.debug_wbuffer_size = fbr_conf_get_ulong("DEBUG_FS_WBUFFER_ALLOC_SIZE", 0);

	fbr_config_reader_ready(reader);
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

	fs->config.reader.magic = FBR_CONFIG_READER_MAGIC;
	fs->config.reader.update_interval = fbr_conf_get_ulong("CONFIG_UPDATE_INTERVAL", 0);

	fbr_fs_config_load(fs);

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
