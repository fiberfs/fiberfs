/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/tree.h"

#define FBR_DINDEX_HEAD_COUNT			1024

struct fbr_dindex_dirhead {
	unsigned				magic;
#define FBR_DINDEX_DIRHEAD_MAGIC		0x85BE0E4D

	struct fbr_dindex_tree			tree;
	pthread_rwlock_t			rwlock;
};

struct fbr_dindex {
	unsigned				magic;
#define FBR_DINDEX_MAGIC			0xF5FCA6A6

	struct fbr_dindex_dirhead		dirheads[FBR_DINDEX_HEAD_COUNT];
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

void _fbr_file_free(struct fbr_file *file);

struct fbr_dindex *
fbr_dindex_alloc(void)
{
	struct fbr_dindex *dindex;

	dindex = calloc(1, sizeof(*dindex));
	assert(dindex);

	dindex->magic = FBR_DINDEX_MAGIC;

	assert(FBR_DINDEX_HEAD_COUNT);

	for (size_t i = 0; i < FBR_DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];

		dirhead->magic = FBR_DINDEX_DIRHEAD_MAGIC;

		RB_INIT(&dirhead->tree);
		assert_zero(pthread_rwlock_init(&dirhead->rwlock, NULL));
	}

	return dindex;
}

static struct fbr_dindex_dirhead *
_dindex_get_dirhead(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	size_t pos = directory->inode % FBR_DINDEX_HEAD_COUNT;

        struct fbr_dindex_dirhead *dirhead = &(dindex->dirheads[pos]);
	fbr_dindex_dirhead_ok(dirhead);

        return dirhead;
}

void
fbr_dindex_add(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);
	assert(directory->inode);

	struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, directory);

	assert_zero(pthread_rwlock_wrlock(&dirhead->rwlock));
	fbr_dindex_dirhead_ok(dirhead);

	assert(directory->state == FBR_DIRSTATE_NONE);
	directory->state = FBR_DIRSTATE_LOADING;

	// dindex ownership
	directory->refcount = 1;

	struct fbr_directory *existing = RB_INSERT(fbr_dindex_tree, &dirhead->tree, directory);
	fbr_ASSERT(!existing, "TODO");

	assert_zero(pthread_rwlock_unlock(&dirhead->rwlock));
}

static struct fbr_directory *
_dindex_get(struct fbr_dindex *dindex, unsigned long inode, int do_refcount)
{
	fbr_dindex_ok(dindex);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	find.inode = inode;

        struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, &find);

        assert_zero(pthread_rwlock_rdlock(&dirhead->rwlock));
        fbr_dindex_dirhead_ok(dirhead);

        struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &dirhead->tree, &find);

	if (directory) {
		fbr_directory_ok(directory);
		assert(directory->refcount);

		if (do_refcount) {
			directory->refcount++;
			assert(directory->refcount);
		}
	}

	assert_zero(pthread_rwlock_unlock(&dirhead->rwlock));

	return directory;
}

struct fbr_directory *
fbr_dindex_get(struct fbr_dindex *dindex, unsigned long inode)
{
	return _dindex_get(dindex, inode, 1);
}

struct fbr_directory *
fbr_dindex_get_forget(struct fbr_dindex *dindex, unsigned long inode)
{
	return _dindex_get(dindex, inode, 0);
}

static void
_dindex_directory_free(struct fbr_directory *directory, int release_files)
{
	fbr_directory_ok(directory);

	struct fbr_file *file, *temp;

	TAILQ_FOREACH_SAFE(file, &directory->file_list, file_entry, temp) {
		fbr_file_ok(file);

		TAILQ_REMOVE(&directory->file_list, file, file_entry);

		struct fbr_file *ret = RB_REMOVE(fbr_filename_tree, &directory->filename_tree,
			file);
		assert(file == ret);

		if (release_files) {
			fbr_file_release(file);
		} else {
			_fbr_file_free(file);
		}
	}

	assert(TAILQ_EMPTY(&directory->file_list));
	assert(RB_EMPTY(&directory->filename_tree));

	assert_zero(pthread_mutex_destroy(&directory->cond_lock));

	fbr_filename_free(&directory->dirname);

	fbr_ZERO(directory);

	free(directory);
}

static void
_dindex_release(struct fbr_dindex *dindex, struct fbr_directory *directory, unsigned int refs)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);
	assert(refs);

	struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, directory);

	assert_zero(pthread_rwlock_wrlock(&dirhead->rwlock));
	fbr_dindex_dirhead_ok(dirhead);
	fbr_directory_ok(directory);

	assert(directory->refcount >= refs);
	directory->refcount -= refs;

	if (directory->refcount) {
		assert_zero(pthread_rwlock_unlock(&dirhead->rwlock));
		return;
	}

	struct fbr_directory *ret = RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);
	assert(directory == ret);

	assert_zero(pthread_rwlock_unlock(&dirhead->rwlock));

	_dindex_directory_free(directory, 1);
}

void
fbr_dindex_release(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	_dindex_release(dindex, directory, 1);
}

void
fbr_dindex_release_count(struct fbr_dindex *dindex, struct fbr_directory *directory,
    unsigned int refs)
{
	_dindex_release(dindex, directory, refs);
}

void
fbr_dindex_free(struct fbr_dindex *dindex)
{
	fbr_dindex_ok(dindex);

	for (size_t i = 0; i < FBR_DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];
		fbr_dindex_dirhead_ok(dirhead);

		struct fbr_directory *directory, *next;

		RB_FOREACH_SAFE(directory, fbr_dindex_tree, &dirhead->tree, next) {
			fbr_directory_ok(directory);

			struct fbr_directory *ret = RB_REMOVE(fbr_dindex_tree, &dirhead->tree,
				directory);
			assert(directory == ret);

			_dindex_directory_free(directory, 0);
		}

		assert(RB_EMPTY(&dirhead->tree));

		assert_zero(pthread_rwlock_destroy(&dirhead->rwlock));

		fbr_ZERO(dirhead);
	}

	fbr_ZERO(dindex);

	free(dindex);
}
