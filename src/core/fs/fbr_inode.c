/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"

#define _INODE_HEAD_COUNT			1024
#define _INODE_START				1000

struct fbr_inode_head {
	unsigned				magic;
#define FBR_INODE_HEAD_MAGIC			0xCE5442D7

	struct fbr_inode_tree			tree;
	pthread_mutex_t				lock;
};

struct fbr_inode {
	unsigned				magic;
#define FBR_INODE_MAGIC				0x452D632A

	struct fbr_inode_head			heads[_INODE_HEAD_COUNT];

	unsigned long				next;
};

#define fbr_inode_ok(inode)					\
{								\
	assert(inode);						\
	assert((inode)->magic == FBR_INODE_MAGIC);		\
}
#define fbr_inode_head_ok(head)					\
{								\
	assert(head);						\
	assert((head)->magic == FBR_INODE_HEAD_MAGIC);		\
}

RB_GENERATE_STATIC(fbr_inode_tree, fbr_file, inode_entry, fbr_file_inode_cmp)

struct fbr_inode *
fbr_inodes_alloc(void)
{
	assert(FBR_INODE_ROOT == 1);
	assert(_INODE_START > FBR_INODE_ROOT);

	struct fbr_inode *inode;

	inode = calloc(1, sizeof(*inode));
	assert(inode);

	inode->magic = FBR_INODE_MAGIC;
	inode->next = _INODE_START;

	assert(_INODE_HEAD_COUNT);

	for (size_t i = 0; i < _INODE_HEAD_COUNT; i++) {
		struct fbr_inode_head *head = &inode->heads[i];

		head->magic = FBR_INODE_HEAD_MAGIC;

		RB_INIT(&head->tree);
		assert_zero(pthread_mutex_init(&head->lock, NULL));
	}

	return inode;
}

static inline struct fbr_inode *
_inode_fs_get(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_inode_ok(fs->inode);

	return fs->inode;
}

unsigned long
fbr_inode_gen(struct fbr_fs *fs)
{
	struct fbr_inode *inode = _inode_fs_get(fs);

	unsigned long inode_next = __sync_fetch_and_add(&inode->next, 1);
	assert(inode_next >= _INODE_START);

	return inode_next;
}

static struct fbr_inode_head *
_inode_get_head(struct fbr_inode *inode, struct fbr_file *file)
{
	fbr_inode_ok(inode);
	fbr_file_ok(file);

	size_t pos = file->inode % _INODE_HEAD_COUNT;

        struct fbr_inode_head *head = &inode->heads[pos];
	fbr_inode_head_ok(head);

        return head;
}


// fuse_lookup and root_file
// File comes from a dindex that has a reference
// Multiple calls ok since file comes from the same dindex
void
fbr_inode_add(struct fbr_fs *fs, struct fbr_file *file)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	fbr_file_ok(file);
	assert(file->inode);

	struct fbr_inode_head *head = _inode_get_head(inode, file);

	assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);
	fbr_file_ok(file);

	fbr_file_ref_inode(fs, file);

	struct fbr_file *existing = RB_INSERT(fbr_inode_tree, &head->tree, file);

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
fbr_inode_take(struct fbr_fs *fs, unsigned long file_inode)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	assert(file_inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = file_inode;

        struct fbr_inode_head *head = _inode_get_head(inode, &find);

        assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inode_tree, &head->tree, &find);
	fbr_file_ok(file);

	fbr_file_ref_inode(fs, file);

	assert_zero(pthread_mutex_unlock(&head->lock));

	return file;
}

// fuse_open, called after taking a inode_ref, should always have a lookup
void
fbr_inode_release(struct fbr_fs *fs, struct fbr_file *file)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	fbr_file_ok(file);

        struct fbr_inode_head *head = _inode_get_head(inode, file);

        assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);
	fbr_file_ok(file);

	struct fbr_file_refcounts refcounts;
	fbr_file_release_inode(fs, file, &refcounts);

	if (refcounts.inode) {
		assert_zero(pthread_mutex_unlock(&head->lock));
		return;
	}

	(void)RB_REMOVE(fbr_inode_tree, &head->tree, file);

	assert_zero(pthread_mutex_unlock(&head->lock));

	if (!refcounts.all) {
		fbr_file_free(fs, file);
	}
}

// fuse_forget, called after fuse_lookup or fuse_create
void
fbr_inode_forget(struct fbr_fs *fs, unsigned long file_inode, unsigned int refs)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	assert(file_inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = file_inode;

        struct fbr_inode_head *head = _inode_get_head(inode, &find);

        assert_zero(pthread_mutex_lock(&head->lock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inode_tree, &head->tree, &find);
	fbr_file_ok(file);

	struct fbr_file_refcounts refcounts;
	fbr_file_forget_inode(fs, file, refs, &refcounts);

	if (refcounts.inode) {
		assert_zero(pthread_mutex_unlock(&head->lock));
		return;
	}

	(void)RB_REMOVE(fbr_inode_tree, &head->tree, file);

	assert_zero(pthread_mutex_unlock(&head->lock));

	if (!refcounts.all) {
		fbr_file_free(fs, file);
	}
}

void
fbr_inodes_free(struct fbr_fs *fs)
{
	struct fbr_inode *inode = _inode_fs_get(fs);

	for (size_t i = 0; i < _INODE_HEAD_COUNT; i++) {
		struct fbr_inode_head *head = &inode->heads[i];
		fbr_inode_head_ok(head);

		struct fbr_file *file, *next;

		RB_FOREACH_SAFE(file, fbr_inode_tree, &head->tree, next) {
			fbr_file_ok(file);

			(void)RB_REMOVE(fbr_inode_tree, &head->tree, file);

			fbr_file_free(fs, file);
		}

		assert(RB_EMPTY(&head->tree));

		assert_zero(pthread_mutex_destroy(&head->lock));

		fbr_ZERO(head);
	}

	fbr_ZERO(inode);
	free(inode);
	fs->inode = NULL;
}
