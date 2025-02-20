/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
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

	TAILQ_HEAD(, fbr_directory)		lru;
	size_t					lru_len;
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

void
fbr_dindex_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	assert_zero(fs->dindex);

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

	TAILQ_INIT(&dindex->lru);

	fs->dindex = dindex;
}

static inline struct fbr_dindex *
_dindex_fs_get(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_dindex_ok(fs->dindex);

	return fs->dindex;
}

static void
_dindex_lru_add(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	if (directory->inode == FBR_INODE_ROOT) {
		return;
	}

	TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);
}

static void
_dindex_lru_move(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	if (directory->inode == FBR_INODE_ROOT) {
		return;
	}

	if (TAILQ_FIRST(&dindex->lru) != directory) {
		TAILQ_REMOVE(&dindex->lru, directory, lru_entry);
		TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);
	}
}

static void
_dindex_lru_remove(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	if (directory->inode == FBR_INODE_ROOT) {
		return;
	}

	TAILQ_REMOVE(&dindex->lru, directory, lru_entry);

	assert(dindex->lru_len);
	dindex->lru_len--;
}

static struct fbr_dindex_dirhead *
_dindex_get_dirhead(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	struct fbr_path_name dirname;
	fbr_path_get_dir(&directory->dirname, &dirname);
	assert(dirname.name);

        unsigned long hash = 5381;
        int c;

        while ((c = *dirname.name++)) {
                hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        }

        struct fbr_dindex_dirhead *dirhead = &(dindex->dirheads[hash % _DINDEX_HEAD_COUNT]);
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

	_dindex_lru_add(dindex, directory);

	fbr_fs_stat_add(&fs->stats.directory_refs);

	assert_zero(pthread_mutex_unlock(&dirhead->lock));
}

struct fbr_directory *
fbr_dindex_take(struct fbr_fs *fs, struct fbr_path_name *dirname)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	assert(dirname);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	fbr_path_init_dir(&find.dirname, dirname->name, dirname->len);

        struct fbr_dindex_dirhead *dirhead = _dindex_get_dirhead(dindex, &find);

        assert_zero(pthread_mutex_lock(&dirhead->lock));
        fbr_dindex_dirhead_ok(dirhead);

        struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &dirhead->tree, &find);

	// TODO directory is null if it hasnt been fetched yet

	fbr_directory_ok(directory);
	assert(directory->refcount);

	directory->refcount++;
	assert(directory->refcount);

	_dindex_lru_move(dindex, directory);

	fbr_fs_stat_add(&fs->stats.directory_refs);

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

		if (!refcounts.all) {
			fbr_file_free(fs, file);
		}
	}

	fbr_inode_release(fs, directory->file);

	assert(TAILQ_EMPTY(&directory->file_list));
	assert(RB_EMPTY(&directory->filename_tree));

	assert_zero(pthread_mutex_destroy(&directory->cond_lock));

	fbr_path_free(&directory->dirname);

	fbr_ZERO(directory);

	free(directory);

	fbr_fs_stat_sub(&fs->stats.directories);
}

void
fbr_dindex_forget(struct fbr_fs *fs, struct fbr_path_name *dirname, fbr_refcount_t refs)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	assert(dirname);
	assert(refs);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	fbr_path_init_dir(&find.dirname, dirname->name, dirname->len);

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

	_dindex_lru_remove(dindex, directory);

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

	_dindex_lru_remove(dindex, directory);

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

	assert(TAILQ_EMPTY(&dindex->lru));
	assert_zero(dindex->lru_len);

	fbr_ZERO(dindex);
	free(dindex);
	fs->dindex = NULL;
}
