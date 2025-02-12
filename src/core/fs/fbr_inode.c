/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"

#define _INODE_START				1000

struct fbr_inode {
	unsigned				magic;
#define FBR_INODE_MAGIC				0x452D632A

	unsigned long				next;
};

#define fbr_inode_ok(inode)					\
{								\
	assert(inode);						\
	assert((inode)->magic == FBR_INODE_MAGIC);		\
}

// TODO release files from inode tree

struct fbr_inode *
fbr_inode_alloc(void)
{
	assert(_INODE_START > 1);

	struct fbr_inode *inode;

	inode = calloc(1, sizeof(*inode));
	assert(inode);

	inode->magic = FBR_INODE_MAGIC;
	inode->next = _INODE_START;

	return inode;
}

unsigned long
fbr_inode_gen(struct fbr_inode *inode)
{
	fbr_inode_ok(inode);

	unsigned long inode_next = __sync_fetch_and_add(&inode->next, 1);
	assert(inode_next >= _INODE_START);

	return inode_next;
}

void
fbr_inode_free(struct fbr_inode *inode)
{
	fbr_inode_ok(inode);

	fbr_ZERO(inode);

	free(inode);
}
