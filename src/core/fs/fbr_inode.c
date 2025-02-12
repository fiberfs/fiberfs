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
	pthread_rwlock_t			rwlock;
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
	assert(_INODE_START > 1);

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
		assert_zero(pthread_rwlock_init(&head->rwlock, NULL));
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

static void
_inode_file_ref(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	assert_zero(pthread_mutex_lock(&file->lock));
	fbr_file_ok(file);

	file->refcount++;
	assert(file->refcount);

	fbr_fs_stat_add(&fs->stats.file_refs);

	assert_zero(pthread_mutex_unlock(&file->lock));
}

void
fbr_inode_add(struct fbr_fs *fs, struct fbr_file *file)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	fbr_file_ok(file);
	assert(file->inode);

	struct fbr_inode_head *head = _inode_get_head(inode, file);

	assert_zero(pthread_rwlock_wrlock(&head->rwlock));
	fbr_inode_head_ok(head);

	// Caller (fuse lookup) owns a reference
	_inode_file_ref(fs, file);

	struct fbr_file *existing = RB_INSERT(fbr_inode_tree, &head->tree, file);

	if (existing) {
		fbr_file_ok(existing);
		assert(existing == file);
	}

	assert_zero(pthread_rwlock_unlock(&head->rwlock));
}

// TODO better understand if this is good to use
struct fbr_file *
fbr_inode_get(struct fbr_fs *fs, unsigned long file_inode)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	assert(file_inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = file_inode;

        struct fbr_inode_head *head = _inode_get_head(inode, &find);

        assert_zero(pthread_rwlock_wrlock(&head->rwlock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inode_tree, &head->tree, &find);

	if (file) {
		fbr_file_ok(file);
		assert(file->refcount);
	}

	assert_zero(pthread_rwlock_unlock(&head->rwlock));

	return file;
}

struct fbr_file *
fbr_inode_ref(struct fbr_fs *fs, unsigned long file_inode)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	assert(file_inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = file_inode;

        struct fbr_inode_head *head = _inode_get_head(inode, &find);

        assert_zero(pthread_rwlock_wrlock(&head->rwlock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inode_tree, &head->tree, &find);

	if (file) {
		fbr_file_ok(file);
		assert(file->refcount);

		// Caller owns a reference
		_inode_file_ref(fs, file);
	}

	assert_zero(pthread_rwlock_unlock(&head->rwlock));

	return file;
}

void
fbr_inode_release(struct fbr_fs *fs, unsigned long inode)
{
	fbr_inode_forget(fs, inode, 1);
}

void
fbr_inode_forget(struct fbr_fs *fs, unsigned long file_inode, unsigned int refs)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	assert(file_inode);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	find.inode = file_inode;

        struct fbr_inode_head *head = _inode_get_head(inode, &find);

        assert_zero(pthread_rwlock_wrlock(&head->rwlock));
	fbr_inode_head_ok(head);

        struct fbr_file *file = RB_FIND(fbr_inode_tree, &head->tree, &find);
	fbr_file_ok(file);
	assert(file->refcount >= refs);

	file->refcount -= refs;

	fbr_fs_stat_sub_count(&fs->stats.file_refs, refs);

	if (file->refcount) {
		assert_zero(pthread_rwlock_unlock(&head->rwlock));
		return;
	}

	struct fbr_file *ret = RB_REMOVE(fbr_inode_tree, &head->tree, file);
	assert(file == ret);

	assert_zero(pthread_rwlock_unlock(&head->rwlock));

	fbr_file_free(fs, file);
}

// TODO this can probably race with another operation?
void
fbr_inode_delete(struct fbr_fs *fs, struct fbr_file *file)
{
	struct fbr_inode *inode = _inode_fs_get(fs);
	fbr_file_ok(file);

        struct fbr_inode_head *head = _inode_get_head(inode, file);

        assert_zero(pthread_rwlock_wrlock(&head->rwlock));
	fbr_inode_head_ok(head);
	fbr_file_ok(file);

	struct fbr_file *ret = RB_REMOVE(fbr_inode_tree, &head->tree, file);
	assert(file == ret);

	assert_zero(pthread_rwlock_unlock(&head->rwlock));
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

			struct fbr_file *ret = RB_REMOVE(fbr_inode_tree, &head->tree, file);
			assert(file == ret);

			fbr_file_free(fs, file);
		}

		assert(RB_EMPTY(&head->tree));

		assert_zero(pthread_rwlock_destroy(&head->rwlock));

		fbr_ZERO(head);
	}

	fbr_ZERO(inode);
	free(inode);
	fs->inode = NULL;
}
