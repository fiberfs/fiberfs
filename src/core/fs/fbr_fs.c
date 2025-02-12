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

	fs->inode = fbr_inodes_alloc();
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

	struct fbr_file *root_file = fbr_file_root_alloc(fs);
	fbr_inode_add(fs, root_file);
}

void
fbr_fs_release_root(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(fs->root);

	fbr_inode_forget(fs, 1, 1);

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
