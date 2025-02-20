/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/context/fbr_callback.h"

/*
 * Each directory has a list of files with references
 * Each directory lives in the dindex and is controlled by the LRU
 * Each directory has a reference to its parent inode file
 * Each file has a parent inode value
 *
 * The root directory doesnt live in the LRU, the fs owns its ref
 * It also owns its parent inode ref
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
fbr_fs_release_root(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(fs->root);

	fbr_dindex_release(fs, fs->root);
	fs->root = NULL;
}

void
fbr_fs_free(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	if (fs->root) {
		fbr_fs_release_root(fs);
	}

	fbr_dindex_free(fs);
	fbr_inodes_free(fs);

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
