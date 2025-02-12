/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_fs.h"

void
fbr_fs_init(struct fbr_fs *fs)
{
	assert(fs);

	fbr_ZERO(fs);

	fs->magic = FBR_FS_MAGIC;

	fs->inode = fbr_inode_alloc();
	fs->dindex = fbr_dindex_alloc();

	fbr_fs_ok(fs);
}

void
fbr_fs_set_root(struct fbr_fs *fs, struct fbr_directory *root)
{
	fbr_fs_ok(fs);
	assert_zero(fs->root);
	fbr_directory_ok(root);
	assert_zero(root->dirname.len);

	fs->root = root;
}

void
fbr_fs_release_root(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(fs->root);

	fbr_directory_release(fs->dindex, fs->root);
	fs->root = NULL;
}

void
fbr_fs_free(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	if (fs->root) {
		fbr_fs_release_root(fs);
	}

	fbr_inode_free(fs->inode);
	fbr_dindex_free(fs->dindex);

	fbr_ZERO(fs);
}

void
fbr_fs_stat_add(unsigned long *stat, size_t value)
{
	assert(stat);

        (void)__sync_add_and_fetch(stat, value);
}
