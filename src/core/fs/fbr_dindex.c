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
#include "core/store/fbr_store.h"

#define _DINDEX_HEAD_COUNT			1024

struct fbr_dindex_dirhead {
	unsigned				magic;
#define FBR_DINDEX_DIRHEAD_MAGIC		0x85BE0E4D

	struct fbr_dindex_tree			tree;
	pthread_mutex_t				lock;
};

TAILQ_HEAD(_dindex_lru_list, fbr_directory);

struct fbr_dindex {
	unsigned				magic;
#define FBR_DINDEX_MAGIC			0xF5FCA6A6

	struct fbr_dindex_dirhead		dirheads[_DINDEX_HEAD_COUNT];

	struct _dindex_lru_list			lru;
	pthread_mutex_t				lru_lock;
	volatile size_t				lru_len;
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

static void _dindex_directory_free(struct fbr_fs *fs, struct fbr_directory *directory);

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
	assert_zero(pthread_mutex_init(&dindex->lru_lock, NULL));

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
_dindex_lru_add(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->refcounts.in_lru);
	assert(directory->refcounts.fs);

	if (directory->inode == FBR_INODE_ROOT) {
		return;
	}

	assert_zero(pthread_mutex_lock(&dindex->lru_lock));

	TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);

	directory->refcounts.in_lru = 1;

	directory->refcounts.fs++;
	assert(directory->refcounts.fs);

	fbr_fs_stat_add(&fs->stats.directory_refs);

	dindex->lru_len++;
	assert(dindex->lru_len);

	assert_zero(pthread_mutex_unlock(&dindex->lru_lock));
}

static void
_dindex_lru_move(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	fbr_directory_ok(directory);

	assert_zero(pthread_mutex_lock(&dindex->lru_lock));

	if (!directory->refcounts.in_lru) {
		assert_zero(pthread_mutex_unlock(&dindex->lru_lock));
		return;
	}

	if (TAILQ_FIRST(&dindex->lru) != directory) {
		TAILQ_REMOVE(&dindex->lru, directory, lru_entry);
		TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);
	}

	assert_zero(pthread_mutex_unlock(&dindex->lru_lock));
}

static void
_dindex_lru_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	fbr_directory_ok(directory);

	assert_zero(pthread_mutex_lock(&dindex->lru_lock));

	if (!directory->refcounts.in_lru) {
		assert_zero(pthread_mutex_unlock(&dindex->lru_lock));
		return;
	}

	TAILQ_REMOVE(&dindex->lru, directory, lru_entry);

	directory->refcounts.in_lru = 0;

	assert(directory->refcounts.fs);
	directory->refcounts.fs--;

	fbr_fs_stat_sub(&fs->stats.directory_refs);

	assert(dindex->lru_len);
	dindex->lru_len--;

	assert_zero(pthread_mutex_unlock(&dindex->lru_lock));
}

static struct fbr_directory *
_dindex_lru_pop(struct fbr_fs *fs)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);

	assert_zero(pthread_mutex_lock(&dindex->lru_lock));

	if (!dindex->lru_len) {
		assert_zero(pthread_mutex_unlock(&dindex->lru_lock));
		return NULL;
	}

	struct fbr_directory *directory = TAILQ_LAST(&dindex->lru, _dindex_lru_list);
	fbr_directory_ok(directory);
	assert(directory->refcounts.in_lru);

	TAILQ_REMOVE(&dindex->lru, directory, lru_entry);
	directory->refcounts.in_lru = 0;

	// We still own a reference but we dont own a proper lock here
	assert(directory->refcounts.fs);

	assert(dindex->lru_len);
	dindex->lru_len--;

	assert_zero(pthread_mutex_unlock(&dindex->lru_lock));

	return directory;
}

static struct fbr_dindex_dirhead *
_dindex_dirhead_get(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	struct fbr_path_name dirname;
	fbr_path_get_dir(&directory->dirname, &dirname);
	assert(dirname.name);

	unsigned long hash = 5381;

	for (size_t i = 0; i < dirname.len; i++) {
		int c = dirname.name[i];
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	struct fbr_dindex_dirhead *dirhead = &(dindex->dirheads[hash % _DINDEX_HEAD_COUNT]);
	fbr_dindex_dirhead_ok(dirhead);

	return dirhead;
}

static struct fbr_dindex_dirhead *
_dindex_LOCK(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);

	struct fbr_dindex_dirhead *dirhead = _dindex_dirhead_get(dindex, directory);

	assert_zero(pthread_mutex_lock(&dirhead->lock));
	fbr_directory_ok(directory);

	return dirhead;
}

static void
_dindex_UNLOCK(struct fbr_dindex_dirhead *dirhead)
{
	fbr_dindex_dirhead_ok(dirhead);
	assert_zero(pthread_mutex_unlock(&dirhead->lock));
}

void
fbr_dindex_add(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->inode);
	assert_zero(directory->refcounts.in_dindex);
	assert_zero(directory->refcounts.in_lru);
	assert_zero(directory->refcounts.fs);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, directory);

	assert(directory->state == FBR_DIRSTATE_NONE);
	directory->state = FBR_DIRSTATE_LOADING;
	directory->creation = fbr_get_time();

	// Caller owns this ref
	directory->refcounts.fs = 1;
	directory->refcounts.in_dindex = 1;

	fbr_fs_stat_add(&fs->stats.directory_refs);

	struct fbr_directory *existing = RB_INSERT(fbr_dindex_tree, &dirhead->tree, directory);
	int free_existing = 0;

	if (existing) {
		fbr_directory_ok(existing);
		assert(existing->refcounts.fs);

		assert(existing->refcounts.in_dindex);
		(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, existing);
		existing->refcounts.in_dindex = 0;

		_dindex_lru_remove(fs, existing);
		assert_zero_dev(existing->refcounts.in_lru);

		// Wait for stale to complete loading
		assert_dev(existing->state >= FBR_DIRSTATE_LOADING);
		if (existing->state == FBR_DIRSTATE_LOADING) {
			fbr_directory_wait_ok(fs, existing);
		}

		// Directory takes a reference
		if (existing->state == FBR_DIRSTATE_OK) {
			existing->refcounts.fs++;
			assert(existing->refcounts.fs);

			assert_zero_dev(directory->stale);
			directory->stale = existing;

			fbr_fs_stat_add(&fs->stats.directory_refs);
		} else if (!existing->refcounts.fs) {
			assert_dev(existing->state == FBR_DIRSTATE_ERROR);
			free_existing = 1;
		}

		assert_zero(RB_INSERT(fbr_dindex_tree, &dirhead->tree, directory));
	} else {
		fbr_fs_stat_add(&fs->stats.directories_dindex);
	}

	_dindex_lru_add(fs, directory);

	_dindex_UNLOCK(dirhead);

	if (free_existing) {
		_dindex_directory_free(fs, existing);
	}
}

struct fbr_directory *
fbr_dindex_take(struct fbr_fs *fs, const struct fbr_path_name *dirname,
    enum fbr_directory_flags flags)
{
	fbr_fs_ok(fs);
	assert(dirname);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	fbr_path_init_dir(&find.dirname, dirname->name, dirname->len);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, &find);

	struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &dirhead->tree, &find);

	if (!directory) {
		_dindex_UNLOCK(dirhead);
		return NULL;
	}

	_dindex_lru_move(fs, directory);

	if (flags & FBR_DIRFLAGS_STALE_OK && directory->stale) {
		fbr_directory_ok(directory->stale);
		assert(directory->stale->state == FBR_DIRSTATE_OK);

		if (directory->state == FBR_DIRSTATE_LOADING) {
			directory = directory->stale;
			assert_zero_dev(directory->stale);
		}
	}

	fbr_directory_ok(directory);
	assert(directory->refcounts.fs);

	directory->refcounts.fs++;
	assert(directory->refcounts.fs);

	fbr_fs_stat_add(&fs->stats.directory_refs);

	_dindex_UNLOCK(dirhead);

	if (flags & FBR_DIRFLAGS_DONT_WAIT) {
		return directory;
	}

	assert(directory->state >= FBR_DIRSTATE_LOADING);
	if (directory->state == FBR_DIRSTATE_LOADING) {
		fbr_directory_wait_ok(fs, directory);
	}

	// TODO we will have to return an error state here
	assert(directory->state == FBR_DIRSTATE_OK);

	return directory;
}

static void
_dindex_directory_free(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->refcounts.in_dindex);
	assert_zero(directory->refcounts.in_lru);

	struct fbr_file *file, *temp;

	TAILQ_FOREACH_SAFE(file, &directory->file_list, file_entry, temp) {
		fbr_file_ok(file);

		TAILQ_REMOVE(&directory->file_list, file, file_entry);

		(void)RB_REMOVE(fbr_filename_tree, &directory->filename_tree, file);

		fbr_file_release_dindex(fs, &file);
		assert_zero_dev(file);

		directory->file_count--;
	}

	fbr_inode_release(fs, &directory->file);
	assert_zero_dev(directory->file);

	assert(TAILQ_EMPTY(&directory->file_list));
	assert(RB_EMPTY(&directory->filename_tree));
	assert_zero(directory->file_count);

	assert_zero(pthread_mutex_destroy(&directory->update_lock));
	assert_zero(pthread_cond_destroy(&directory->update));

	fbr_path_free(&directory->dirname);

	fbr_ZERO(directory);

	free(directory);

	fbr_fs_stat_sub(&fs->stats.directories);
}

// NOTE: always release after replying to fuse
void
fbr_dindex_release(struct fbr_fs *fs, struct fbr_directory **directory_ref)
{
	fbr_fs_ok(fs);
	assert(*directory_ref);

	struct fbr_directory *directory = *directory_ref;
	fbr_directory_ok(directory);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, directory);

	*directory_ref = NULL;

	assert(directory->refcounts.fs);
	directory->refcounts.fs--;

	fbr_fs_stat_sub(&fs->stats.directory_refs);

	if (directory->refcounts.fs) {
		_dindex_UNLOCK(dirhead);
		return;
	}

	if (directory->refcounts.in_dindex) {
		(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);
		directory->refcounts.in_dindex = 0;

		fbr_fs_stat_sub(&fs->stats.directories_dindex);
	}

	assert_zero_dev(directory->refcounts.in_lru);

	_dindex_UNLOCK(dirhead);

	if (directory->state == FBR_DIRSTATE_OK) {
		fbr_directory_expire(fs, directory, NULL);
	}

	_dindex_directory_free(fs, directory);
}

static void
_dindex_lru_pop_release(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_directory *directory = _dindex_lru_pop(fs);

	if (!directory) {
		return;
	}

	// Release LRU reference
	fbr_directory_ok(directory);

	fbr_dindex_release(fs, &directory);
	assert_zero_dev(directory);
}

void
fbr_dindex_lru_purge(struct fbr_fs *fs, size_t lru_max)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);

	size_t attempts = dindex->lru_len + 1;

	while (dindex->lru_len > lru_max && attempts) {
		_dindex_lru_pop_release(fs);
		attempts--;
	}
}

void
fbr_dindex_debug(struct fbr_fs *fs, fbr_dindex_debug_f *callback)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	assert(callback);

	for (size_t i = 0; i < _DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];

		assert_zero(pthread_mutex_lock(&dirhead->lock));
		fbr_dindex_dirhead_ok(dirhead);

		struct fbr_directory *directory;

		RB_FOREACH(directory, fbr_dindex_tree, &dirhead->tree) {
			fbr_directory_ok(directory);

			callback(fs, directory);
		}

		assert_zero(pthread_mutex_unlock(&dirhead->lock));
	}
}

void
fbr_dindex_free_all(struct fbr_fs *fs)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);

	for (size_t i = 0; i < _DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];
		fbr_dindex_dirhead_ok(dirhead);

		struct fbr_directory *directory, *next;

		RB_FOREACH_SAFE(directory, fbr_dindex_tree, &dirhead->tree, next) {
			fbr_directory_ok(directory);

			assert(directory->refcounts.in_dindex);
			(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);
			directory->refcounts.in_dindex = 0;

			_dindex_lru_remove(fs, directory);

			fbr_fs_stat_sub(&fs->stats.directories_dindex);

			_dindex_directory_free(fs, directory);
		}

		assert(RB_EMPTY(&dirhead->tree));

		assert_zero(pthread_mutex_destroy(&dirhead->lock));

		fbr_ZERO(dirhead);
	}

	assert(TAILQ_EMPTY(&dindex->lru));
	assert_zero(dindex->lru_len);
	assert_zero(pthread_mutex_destroy(&dindex->lru_lock));

	fbr_ZERO(dindex);
	free(dindex);
	fs->dindex = NULL;
}
