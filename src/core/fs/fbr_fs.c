/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/context/fbr_callback.h"

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

	fbr_fs_ok(fs);

	fbr_context_request_init();

	return fs;
}

void
fbr_fs_set_root(struct fbr_fs *fs, struct fbr_directory *root)
{
	fbr_fs_ok(fs);
	assert_zero(fs->root);
	fbr_directory_ok(root);

	fs->root = root;
}

void
fbr_fs_release_root(struct fbr_fs *fs, int release_root_inode)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(fs->root);

	fbr_dindex_lru_purge(fs, 0);

	fbr_dindex_release(fs, &fs->root);
	assert_zero_dev(fs->root);

	if (release_root_inode) {
		fbr_inode_forget(fs, FBR_INODE_ROOT, 1);
	}
}

void
fbr_fs_free(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	if (fs->root) {
		fbr_fs_release_root(fs, 1);
	}

	fbr_dindex_free_all(fs);
	fbr_inodes_free_all(fs);

	fbr_ZERO(fs);

	free(fs);

	fbr_context_request_finish();
}

void
fbr_fs_stat_add_count(unsigned long *stat, unsigned long value)
{
	assert(stat);

	(void)__sync_add_and_fetch(stat, value);
}

void
fbr_fs_stat_add(unsigned long *stat)
{
	fbr_fs_stat_add_count(stat, 1);
}

void
fbr_fs_stat_sub_count(unsigned long *stat, unsigned long value)
{
	assert(stat);

	(void)__sync_sub_and_fetch(stat, value);
}

void
fbr_fs_stat_sub(unsigned long *stat)
{
	fbr_fs_stat_sub_count(stat, 1);
}

fbr_id_t
fbr_id_gen(void)
{
	struct timespec ts;
        assert_zero(clock_gettime(CLOCK_REALTIME, &ts));

	unsigned long timestamp = ts.tv_sec - 1735689600;
	assert(timestamp < FBR_ID_TIMEBITS_MAX);

	struct fbr_id id;
	id.parts.timestamp = timestamp;

	long rand = random() % FBR_ID_RANDBITS_MAX;
	id.parts.random = rand;

	return id.value;
}

size_t
fbr_id_string(fbr_id_t value, char *buffer, size_t buffer_len)
{
	assert(value);
	assert(buffer);
	assert(buffer_len);

	struct fbr_id id;
	id.value = value;

	unsigned long timestamp = id.parts.timestamp;
	unsigned long rand = id.parts.random;

	int ret = snprintf(buffer, buffer_len, "%lu-%lu", timestamp, rand);

	if (ret < 0 || (size_t)ret >= buffer_len) {
		return 0;
	}

	return (size_t)ret;
}
