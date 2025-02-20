/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

#define _INODE_START				1000
#define _INODES_HEAD_COUNT			1024

struct fbr_inodes_head {
	unsigned				magic;
#define FBR_INODES_HEAD_MAGIC			0xCE5442D7

	struct fbr_inodes_tree			tree;
	pthread_mutex_t				lock;
};

struct fbr_inodes {
	unsigned				magic;
#define FBR_INODES_MAGIC			0x452D632A

	struct fbr_inodes_head			heads[_INODES_HEAD_COUNT];

	fbr_inode_t				next;
};

#define fbr_inodes_ok(inodes)					\
{								\
	assert(inodes);						\
	assert((inodes)->magic == FBR_INODES_MAGIC);		\
}
#define fbr_inode_head_ok(head)					\
{								\
	assert(head);						\
	assert((head)->magic == FBR_INODES_HEAD_MAGIC);		\
}

RB_GENERATE_STATIC(fbr_inodes_tree, fbr_file, inode_entry, fbr_file_inode_cmp)

void
fbr_inodes_alloc(struct fbr_fs *fs)
{
	assert(_INODE_START > FBR_INODE_ROOT);

	fbr_fs_ok(fs);
	assert_zero(fs->inodes);

	struct fbr_inodes *inodes;

	inodes = calloc(1, sizeof(*inodes));
	assert(inodes);

	inodes->magic = FBR_INODES_MAGIC;
	inodes->next = _INODE_START;

	assert(_INODES_HEAD_COUNT);

	for (size_t i = 0; i < _INODES_HEAD_COUNT; i++) {
		struct fbr_inodes_head *head = &inodes->heads[i];

		head->magic = FBR_INODES_HEAD_MAGIC;

		RB_INIT(&head->tree);
		assert_zero(pthread_mutex_init(&head->lock, NULL));
	}

	fs->inodes = inodes;
}

static inline struct fbr_inodes *
_inodes_fs_get(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_inodes_ok(fs->inodes);

	return fs->inodes;
}

fbr_inode_t
fbr_inode_gen(struct fbr_fs *fs)
{
	struct fbr_inodes *inodes = _inodes_fs_get(fs);

	fbr_inode_t inode_next = __sync_fetch_and_add(&inodes->next, 1);
	assert(inode_next >= _INODE_START);

	return inode_next;
}

static struct fbr_inodes_head *
_inodes_get_head(struct fbr_inodes *inodes, struct fbr_file *file)
{
	fbr_inodes_ok(inodes);
	fbr_file_ok(file);

	size_t pos = file->inode % _INODES_HEAD_COUNT;

        struct fbr_inodes_head *head = &inodes->heads[pos];
	fbr_inode_head_ok(head);

        return head;
}


// fuse_lookup and root_file
// File comes from a dindex that has a reference
// Multiple calls ok since file comes from the same dindex
void
fbr_inode_add(struct fbr_fs *fs, struct fbr_file *file)
{
	struct fbr_inodes *inodes = _inodes_fs_get(fs);
	fbr_file_ok(file);
	assert(file->inode);

	struct fbr_inodes_head *head = _inodes_get_head(inodes, file);

	assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);
	fbr_file_ok(file);

	fbr_file_ref_inode(fs, file);

	struct fbr_file *existing = RB_INSERT(fbr_inodes_tree, &head->tree, file);

	if (existing) {
		fbr_file_ok(existing);
		assert(existing == file);
	}

	assert_zero(pthread_mutex_unlock(&head->lock));
}

// fuse_getattr and fuse_readdir
// TODO what is the context here? Do we always have a fuse_lookup?
// dindex should pull a reference to its file so it can get attributes

// fuse_open, fuse_lookup is always done before
// root_file also uses this, it always owns a reference
struct fbr_file *
fbr_inode_take(struct fbr_fs *fs, fbr_inode_t inode)
{
	struct fbr_inodes *inodes = _inodes_fs_get(fs);
	assert(inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = inode;

        struct fbr_inodes_head *head = _inodes_get_head(inodes, &find);

        assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inodes_tree, &head->tree, &find);
	fbr_file_ok(file);

	fbr_file_ref_inode(fs, file);

	assert_zero(pthread_mutex_unlock(&head->lock));

	return file;
}

// fuse_open, called after taking a inode_ref, should always have a lookup
void
fbr_inode_release(struct fbr_fs *fs, struct fbr_file **file_ref)
{
	struct fbr_inodes *inodes = _inodes_fs_get(fs);
	assert(file_ref);

	struct fbr_file *file = *file_ref;
	fbr_file_ok(file);
	*file_ref = NULL;

        struct fbr_inodes_head *head = _inodes_get_head(inodes, file);

        assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);
	fbr_file_ok(file);

	struct fbr_file_refcounts refcounts;
	fbr_file_release_inode(fs, file, &refcounts);

	if (refcounts.inode) {
		assert_zero(pthread_mutex_unlock(&head->lock));
		return;
	}

	(void)RB_REMOVE(fbr_inodes_tree, &head->tree, file);

	assert_zero(pthread_mutex_unlock(&head->lock));

	if (!refcounts.all) {
		fbr_file_free(fs, file);
	}
}

// fuse_forget, called after fuse_lookup or fuse_create
void
fbr_inode_forget(struct fbr_fs *fs, fbr_inode_t inode, fbr_refcount_t refs)
{
	struct fbr_inodes *inodes = _inodes_fs_get(fs);
	assert(inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = inode;

        struct fbr_inodes_head *head = _inodes_get_head(inodes, &find);

        assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inodes_tree, &head->tree, &find);
	fbr_file_ok(file);

	struct fbr_file_refcounts refcounts;
	fbr_file_forget_inode(fs, file, refs, &refcounts);

	if (refcounts.inode) {
		assert_zero(pthread_mutex_unlock(&head->lock));
		return;
	}

	(void)RB_REMOVE(fbr_inodes_tree, &head->tree, file);

	assert_zero(pthread_mutex_unlock(&head->lock));

	if (!refcounts.all) {
		fbr_file_free(fs, file);
	}
}

void
fbr_inodes_free_all(struct fbr_fs *fs)
{
	struct fbr_inodes *inodes = _inodes_fs_get(fs);

	for (size_t i = 0; i < _INODES_HEAD_COUNT; i++) {
		struct fbr_inodes_head *head = &inodes->heads[i];
		fbr_inode_head_ok(head);

		struct fbr_file *file, *next;

		RB_FOREACH_SAFE(file, fbr_inodes_tree, &head->tree, next) {
			fbr_file_ok(file);

			(void)RB_REMOVE(fbr_inodes_tree, &head->tree, file);

			fbr_file_free(fs, file);
		}

		assert(RB_EMPTY(&head->tree));

		assert_zero(pthread_mutex_destroy(&head->lock));

		fbr_ZERO(head);
	}

	fbr_ZERO(inodes);
	free(inodes);
	fs->inodes = NULL;
}
