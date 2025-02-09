/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "fiberfs.h"
#include "fbr_core_fs.h"

#define _CORE_FS_INODE_START			1000

void
fbr_core_fs_init(struct fbr_core_fs *fs)
{
	assert(fs);
	assert(_CORE_FS_INODE_START > 1);

	fbr_ZERO(fs);

	fs->magic = FBR_CORE_FS_MAGIC;

	fs->inode_next = _CORE_FS_INODE_START;
	fs->dindex = fbr_dindex_alloc();

	fbr_core_fs_ok(fs);
}

unsigned long
fbr_core_fs_gen_inode(struct fbr_core_fs *fs)
{
	fbr_core_fs_ok(fs);

	unsigned long inode = __sync_fetch_and_add(&fs->inode_next, 1);
	assert(inode > 1);

	return inode;
}

void
fbr_core_fs_free(struct fbr_core_fs *fs)
{
	fbr_core_fs_ok(fs);

	fbr_dindex_free(fs->dindex);

	fbr_ZERO(fs);
}
