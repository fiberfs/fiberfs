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

#define fbr_dindex_ok(dindex)			fbr_magic_check(dindex, FBR_DINDEX_MAGIC)
#define fbr_dindex_dirhead_ok(dirhead)		fbr_magic_check(dirhead, FBR_DINDEX_DIRHEAD_MAGIC)

RB_GENERATE_STATIC(fbr_dindex_tree, fbr_directory, dindex_entry, fbr_directory_cmp)

void
fbr_dindex_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	assert_zero(fs->dindex);
	assert_dev(_DINDEX_HEAD_COUNT);

	struct fbr_dindex *dindex;

	dindex = calloc(1, sizeof(*dindex));
	assert(dindex);

	dindex->magic = FBR_DINDEX_MAGIC;

	for (size_t i = 0; i < _DINDEX_HEAD_COUNT; i++) {
		struct fbr_dindex_dirhead *dirhead = &dindex->dirheads[i];

		dirhead->magic = FBR_DINDEX_DIRHEAD_MAGIC;

		RB_INIT(&dirhead->tree);
		pt_assert(pthread_mutex_init(&dirhead->lock, NULL));
	}

	TAILQ_INIT(&dindex->lru);
	pt_assert(pthread_mutex_init(&dindex->lru_lock, NULL));

	fs->dindex = dindex;
}

static inline struct fbr_dindex *
_dindex_fs_get(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	fbr_dindex_ok(fs->dindex);

	return fs->dindex;
}

static inline void
_dindex_ref(struct fbr_fs *fs, struct fbr_directory *directory)
{
	directory->refcounts.fs++;
	assert(directory->refcounts.fs);

	fbr_fs_stat_add(&fs->stats.directory_refs);
}

static inline void
_dindex_deref(struct fbr_fs *fs, struct fbr_directory *directory)
{
	assert(directory->refcounts.fs);
	directory->refcounts.fs--;

	fbr_fs_stat_sub(&fs->stats.directory_refs);
}

static void
_dindex_lru_add(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = fs->dindex;
	assert_zero(directory->refcounts.in_lru);
	assert(directory->refcounts.fs);

	pt_assert(pthread_mutex_lock(&dindex->lru_lock));

	TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);
	directory->refcounts.in_lru = 1;

	_dindex_ref(fs, directory);

	dindex->lru_len++;
	assert(dindex->lru_len);

	pt_assert(pthread_mutex_unlock(&dindex->lru_lock));
}

static void
_dindex_lru_move(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = fs->dindex;

	pt_assert(pthread_mutex_lock(&dindex->lru_lock));

	if (!directory->refcounts.in_lru) {
		pt_assert(pthread_mutex_unlock(&dindex->lru_lock));
		return;
	}

	if (TAILQ_FIRST(&dindex->lru) != directory) {
		TAILQ_REMOVE(&dindex->lru, directory, lru_entry);
		TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);
	}

	pt_assert(pthread_mutex_unlock(&dindex->lru_lock));
}

static void
_dindex_lru_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	struct fbr_dindex *dindex = fs->dindex;

	pt_assert(pthread_mutex_lock(&dindex->lru_lock));

	if (!directory->refcounts.in_lru) {
		pt_assert(pthread_mutex_unlock(&dindex->lru_lock));
		return;
	}

	TAILQ_REMOVE(&dindex->lru, directory, lru_entry);
	directory->refcounts.in_lru = 0;

	_dindex_deref(fs, directory);

	assert(dindex->lru_len);
	dindex->lru_len--;

	pt_assert(pthread_mutex_unlock(&dindex->lru_lock));
}

static struct fbr_directory *
_dindex_lru_pop(struct fbr_fs *fs)
{
	struct fbr_dindex *dindex = fs->dindex;

	pt_assert(pthread_mutex_lock(&dindex->lru_lock));

	if (!dindex->lru_len) {
		pt_assert(pthread_mutex_unlock(&dindex->lru_lock));
		return NULL;
	}

	struct fbr_directory *directory = TAILQ_LAST(&dindex->lru, _dindex_lru_list);
	fbr_directory_ok(directory);
	assert_dev(directory->refcounts.in_lru);

	TAILQ_REMOVE(&dindex->lru, directory, lru_entry);

	// Do root last
	if (dindex->lru_len > 1 && directory->inode == FBR_INODE_ROOT) {
		TAILQ_INSERT_HEAD(&dindex->lru, directory, lru_entry);

		directory = TAILQ_LAST(&dindex->lru, _dindex_lru_list);
		fbr_directory_ok(directory);
		assert_dev(directory->inode != FBR_INODE_ROOT);
		assert_dev(directory->refcounts.in_lru);

		TAILQ_REMOVE(&dindex->lru, directory, lru_entry);
	}

	directory->refcounts.in_lru = 0;

	// We still own a reference but we dont own a proper lock here
	assert(directory->refcounts.fs);

	assert(dindex->lru_len);
	dindex->lru_len--;

	pt_assert(pthread_mutex_unlock(&dindex->lru_lock));

	return directory;
}

static struct fbr_dindex_dirhead *
_dindex_dirhead_get(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	assert_dev(dindex);
	assert_dev(directory);

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);
	assert_dev(dirname.name);

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
	struct fbr_dindex *dindex = fs->dindex;

	struct fbr_dindex_dirhead *dirhead = _dindex_dirhead_get(dindex, directory);

	pt_assert(pthread_mutex_lock(&dirhead->lock));
	fbr_directory_ok(directory);

	return dirhead;
}

static void
_dindex_UNLOCK(struct fbr_dindex_dirhead *dirhead)
{
	fbr_dindex_dirhead_ok(dirhead);
	pt_assert(pthread_mutex_unlock(&dirhead->lock));
}

struct fbr_directory *
fbr_dindex_add(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->inode);
	assert(directory->state == FBR_DIRSTATE_NONE);
	assert_zero(directory->refcounts.in_dindex);
	assert_zero(directory->refcounts.in_lru);
	assert_zero(directory->refcounts.fs);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, directory);

	struct fbr_directory *existing = RB_FIND(fbr_dindex_tree, &dirhead->tree, directory);

	if (existing) {
		fbr_directory_ok(existing);
		assert(existing->refcounts.fs);
		assert(existing->refcounts.in_dindex);

		int newer = fbr_directory_new_cmp(directory, existing);

		if (newer < 0) {
			// Directory inode too old
			directory->state = FBR_DIRSTATE_ERROR;
			_dindex_ref(fs, directory);
			_dindex_lru_move(fs, existing);

			_dindex_UNLOCK(dirhead);

			return directory;
		} else if (existing->state == FBR_DIRSTATE_LOADING) {
			// Caller must wait for loading to complete
			_dindex_ref(fs, existing);
			_dindex_lru_move(fs, existing);

			_dindex_UNLOCK(dirhead);

			return existing;
		}

		// Existing is now previous
		assert_dev(existing->state == FBR_DIRSTATE_OK);
		assert_zero_dev(existing->previous);
		assert_zero_dev(existing->next);

		(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, existing);
		existing->refcounts.in_dindex = 0;

		_dindex_lru_remove(fs, existing);
		assert_zero_dev(existing->refcounts.in_lru);

		// directory will take ownership
		_dindex_ref(fs, existing);

		assert_zero_dev(directory->previous);
		directory->previous = existing;
	} else {
		fbr_fs_stat_add(&fs->stats.directories_dindex);
	}

	directory->state = FBR_DIRSTATE_LOADING;
	directory->version = fbr_id_gen();
	directory->creation = fbr_get_time();

	// Caller owns this ref
	_dindex_ref(fs, directory);

	assert_zero(RB_INSERT(fbr_dindex_tree, &dirhead->tree, directory));
	directory->refcounts.in_dindex = 1;

	_dindex_lru_add(fs, directory);

	_dindex_UNLOCK(dirhead);

	return directory;
}

struct fbr_directory *
fbr_dindex_take(struct fbr_fs *fs, const struct fbr_path_name *dirname, int wait_for_new)
{
	fbr_fs_ok(fs);
	assert(dirname);

	struct fbr_directory find;
	struct fbr_path_shared path;
	find.magic = FBR_DIRECTORY_MAGIC;
	fbr_path_shared_init(&path, dirname);
	find.path = &path;

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, &find);

	struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &dirhead->tree, &find);

	if (!directory) {
		_dindex_UNLOCK(dirhead);
		return NULL;
	}

	fbr_directory_ok(directory);
	assert(directory->refcounts.fs);

	_dindex_lru_move(fs, directory);

	if (!wait_for_new && directory->previous) {
		fbr_directory_ok(directory->previous);
		assert(directory->state == FBR_DIRSTATE_LOADING);
		assert(directory->previous->state == FBR_DIRSTATE_OK);
		assert(directory->previous->refcounts.fs);
		assert_zero_dev(directory->previous->previous);
		assert_zero_dev(directory->previous->next);

		directory = directory->previous;
	}

	_dindex_ref(fs, directory);

	if (directory->state == FBR_DIRSTATE_LOADING) {
		pt_assert(pthread_cond_wait(&directory->update, &dirhead->lock));
	} else {
		assert_dev(directory->state == FBR_DIRSTATE_OK);
	}

	assert_dev(directory->state >= FBR_DIRSTATE_OK);

	_dindex_UNLOCK(dirhead);

	return directory;
}

void
fbr_directory_set_state(struct fbr_fs *fs, struct fbr_directory *directory,
    enum fbr_directory_state state)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(state == FBR_DIRSTATE_OK || state == FBR_DIRSTATE_ERROR);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, directory);

	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	directory->state = state;
	directory->creation = fbr_get_time();

	int release_previous = 0;
	struct fbr_directory *previous = directory->previous;

	if (previous) {
		fbr_directory_ok(previous);
		assert(previous->state == FBR_DIRSTATE_OK);
		assert_zero_dev(previous->refcounts.in_dindex);
		assert_zero_dev(previous->refcounts.in_lru);
		assert_zero_dev(previous->previous);
		assert_zero_dev(previous->next);
		assert_zero_dev(previous->expired);
	}

	if (state == FBR_DIRSTATE_ERROR) {
		assert(directory->refcounts.fs);

		if (directory->refcounts.in_dindex) {
			(void)RB_REMOVE(fbr_dindex_tree, &dirhead->tree, directory);
			directory->refcounts.in_dindex = 0;

			fbr_fs_stat_sub(&fs->stats.directories_dindex);
		}

		_dindex_lru_remove(fs, directory);
		assert_zero_dev(directory->refcounts.in_lru);

		// Swap in previous
		if (previous) {
			directory->previous = NULL;
			release_previous = 1;

			struct fbr_directory *existing =
				RB_INSERT(fbr_dindex_tree, &dirhead->tree, previous);

			if (existing) {
				fbr_directory_ok(existing);
			} else {
				previous->refcounts.in_dindex = 1;
				fbr_fs_stat_add(&fs->stats.directories_dindex);

				_dindex_lru_add(fs, previous);
			}
		}
	} else {
		assert_dev(state == FBR_DIRSTATE_OK);

		if (previous) {
			directory->previous = NULL;
			release_previous = 1;

			// Store directory as next for future invalidation
			// Note will chain references to the oldest generation
			if (fs->config.dentry_ttl <= 0) {
				_dindex_ref(fs, directory);
				previous->next = directory;
			}
		}
	}

	pt_assert(pthread_cond_broadcast(&directory->update));

	_dindex_UNLOCK(dirhead);

	if (release_previous) {
		fbr_dindex_release(fs, &previous);
	}
}

void
fbr_directory_wait_ok(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_LOADING);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, directory);

	if (directory->state == FBR_DIRSTATE_LOADING) {
		pt_assert(pthread_cond_wait(&directory->update, &dirhead->lock));
	}

	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_OK);

	_dindex_UNLOCK(dirhead);
}

// NOTE: Always release after replying to fuse
// This can call fuse_lowlevel_notify_inval_entry() on expiration
// See: https://libfuse.github.io/doxygen/fuse__lowlevel_8h.html#ab14032b74b0a57a2b3155dd6ba8d6095
void
fbr_dindex_release(struct fbr_fs *fs, struct fbr_directory **directory_ref)
{
	fbr_fs_ok(fs);
	assert(*directory_ref);

	struct fbr_directory *directory = *directory_ref;
	fbr_directory_ok(directory);

	struct fbr_dindex_dirhead *dirhead = _dindex_LOCK(fs, directory);

	*directory_ref = NULL;

	_dindex_deref(fs, directory);

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

	fbr_directory_free(fs, directory);
}

static void
_dindex_lru_pop_release(struct fbr_fs *fs)
{
	assert_dev(fs);

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

		pt_assert(pthread_mutex_lock(&dirhead->lock));
		fbr_dindex_dirhead_ok(dirhead);

		struct fbr_directory *directory;
		RB_FOREACH(directory, fbr_dindex_tree, &dirhead->tree) {
			fbr_directory_ok(directory);

			callback(fs, directory);
		}

		pt_assert(pthread_mutex_unlock(&dirhead->lock));
	}
}

void
fbr_dindex_free_all(struct fbr_fs *fs)
{
	struct fbr_dindex *dindex = _dindex_fs_get(fs);
	assert(fs->shutdown);

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

			fbr_directory_free(fs, directory);
		}

		assert(RB_EMPTY(&dirhead->tree));

		pt_assert(pthread_mutex_destroy(&dirhead->lock));

		fbr_ZERO(dirhead);
	}

	assert_zero_dev(fs->stats.directories_dindex);

	assert(TAILQ_EMPTY(&dindex->lru));
	assert_zero(dindex->lru_len);
	pt_assert(pthread_mutex_destroy(&dindex->lru_lock));

	fbr_ZERO(dindex);
	free(dindex);
	fs->dindex = NULL;
}
