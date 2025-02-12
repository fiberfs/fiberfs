/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/tree.h"

#define _DINDEX_HEAD_COUNT			1024

struct fbr_dindex_dirhead {
	unsigned				magic;
#define FBR_DINDEX_DIRHEAD_MAGIC		0x85BE0E4D

	struct fbr_dindex_tree			tree;
	pthread_mutex_t				lock;
};

struct fbr_dindex {
	unsigned				magic;
#define FBR_DINDEX_MAGIC			0xF5FCA6A6

	struct fbr_dindex_dirhead		dirheads[_DINDEX_HEAD_COUNT];
};

#define fbr_dindex_ok(dindex)					\
{								\
	assert(dindex);						\
	assert((dindex)->magic == FBR_DINDEX_MAGIC);		\
}
#define fbr_dindex_dirhead_ok(dirhead)				\
{								\
	assert(dirhead);					\
	assert((dirhead)->magic == FBR_DINDEX_DIRHEAD_MAGIC);	\
}

RB_GENERATE_STATIC(fbr_dindex_tree, fbr_directory, dindex_entry, fbr_directory_cmp)

struct fbr_dindex *
fbr_dindex_alloc(void)
{
	struct fbr_dindex *dindex;

	dindex = calloc(1, sizeof(*dindex));
	assert(dindex);

	dindex->magic = FBR_DINDEX_MAGIC;

	assert(_DINDEX_HEAD_COUNT);

	for (size_t i = 0; i < _DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];

		dirhead->magic = FBR_DINDEX_DIRHEAD_MAGIC;

		RB_INIT(&dirhead->tree);
		assert_zero(pthread_mutex_init(&dirhead->lock, NULL));
	}

	return dindex;
}

static inline struct fbr_dindex *
_dindex_fs_get(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_dindex_ok(fs->dindex);

	return fs->dindex;
}

static struct fbr_dindex_dirhead *
_dindex_get_dirhead(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	size_t pos = directory->inode % _DINDEX_HEAD_COUNT;

        struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[pos];
	fbr_dindex_dirhead_ok(dirhead);

        return dirhead;
}

void
fbr_dindex_add(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	fbr_directory_ok(directory);
	assert(directory->inode);

	struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, directory);

	assert_zero(pthread_mutex_lock(&dirhead->lock));
	fbr_dindex_dirhead_ok(dirhead);

	assert(directory->state == FBR_DIRSTATE_NONE);
	directory->state = FBR_DIRSTATE_LOADING;

	// dindex ownership
	directory->refcount = 1;

	struct fbr_directory *existing = RB_INSERT(fbr_dindex_tree, &dirhead->tree, directory);
	fbr_ASSERT(!existing, "TODO");

	fbr_fs_stat_add(&fs->stats.directory_refs);

	assert_zero(pthread_mutex_unlock(&dirhead->lock));
}

struct fbr_directory *
fbr_dindex_get(struct fbr_fs *fs, unsigned long inode)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	assert(inode);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	find.inode = inode;

        struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, &find);

        assert_zero(pthread_mutex_lock(&dirhead->lock));
        fbr_dindex_dirhead_ok(dirhead);

        struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &dirhead->tree, &find);

	if (directory) {
		fbr_directory_ok(directory);
		assert(directory->refcount);

		directory->refcount++;
		assert(directory->refcount);

		fbr_fs_stat_add(&fs->stats.directory_refs);
	}

	assert_zero(pthread_mutex_unlock(&dirhead->lock));

	return directory;
}

static void
_dindex_directory_free(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_file *file, *temp;

	TAILQ_FOREACH_SAFE(file, &directory->file_list, file_entry, temp) {
		fbr_file_ok(file);

		TAILQ_REMOVE(&directory->file_list, file, file_entry);

		(void)RB_REMOVE(fbr_filename_tree, &directory->filename_tree, file);

		struct fbr_file_refcounts refcounts;
		fbr_file_release_dindex(fs, file, &refcounts);

		if (refcounts.dindex + refcounts.inode == 0) {
			fbr_file_free(fs, file);
		}
	}

	assert(TAILQ_EMPTY(&directory->file_list));
	assert(RB_EMPTY(&directory->filename_tree));

	assert_zero(pthread_mutex_destroy(&directory->cond_lock));

	fbr_filename_free(&directory->dirname);

	fbr_ZERO(directory);

	free(directory);

	fbr_fs_stat_sub(&fs->stats.directories);
}

void
fbr_dindex_forget(struct fbr_fs *fs, unsigned long inode, unsigned int refs)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	assert(inode);
	assert(refs);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	find.inode = inode;

        struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, &find);

        assert_zero(pthread_mutex_lock(&dirhead->lock));
        fbr_dindex_dirhead_ok(dirhead);

        struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &dirhead->tree, &find);
	fbr_directory_ok(directory);

	assert(directory->refcount >= refs);
	directory->refcount -= refs;

	fbr_fs_stat_sub_count(&fs->stats.directory_refs, refs);

	if (directory->refcount) {
		assert_zero(pthread_mutex_unlock(&dirhead->lock));
		return;
	}

	(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);

	assert_zero(pthread_mutex_unlock(&dirhead->lock));

	_dindex_directory_free(fs, directory);
}

void
fbr_dindex_release(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	fbr_directory_ok(directory);

	struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, directory);

	assert_zero(pthread_mutex_lock(&dirhead->lock));
	fbr_dindex_dirhead_ok(dirhead);
	fbr_directory_ok(directory);

	assert(directory->refcount);
	directory->refcount--;

	fbr_fs_stat_sub(&fs->stats.directory_refs);

	if (directory->refcount) {
		assert_zero(pthread_mutex_unlock(&dirhead->lock));
		return;
	}

	(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);

	assert_zero(pthread_mutex_unlock(&dirhead->lock));

	_dindex_directory_free(fs, directory);
}

void
fbr_dindex_free(struct fbr_fs *fs)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);

	for (size_t i = 0; i < _DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];
		fbr_dindex_dirhead_ok(dirhead);

		struct fbr_directory *directory, *next;

		RB_FOREACH_SAFE(directory, fbr_dindex_tree, &dirhead->tree, next) {
			fbr_directory_ok(directory);

			(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);

			_dindex_directory_free(fs, directory);
		}

		assert(RB_EMPTY(&dirhead->tree));

		assert_zero(pthread_mutex_destroy(&dirhead->lock));

		fbr_ZERO(dirhead);
	}

	fbr_ZERO(dindex);
	free(dindex);
	fs->dindex = NULL;
}
