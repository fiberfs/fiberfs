/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_core_fs.h"
#include "data/tree.h"

#define FBR_DINDEX_BUCKET_COUNT		32

struct fbr_dindex_bucket {
	unsigned				magic;
#define FBR_DINDEX_BUCKET_MAGIC			0x85BE0E4D

	struct fbr_dindex_tree			tree;
	pthread_rwlock_t			rwlock;
};

struct fbr_dindex {
	unsigned				magic;
#define FBR_DINDEX_MAGIC			0xF5FCA6A6

	struct fbr_dindex_bucket		buckets[FBR_DINDEX_BUCKET_COUNT];
};

#define fbr_dindex_ok(dindex)					\
{								\
	assert(dindex);						\
	assert((dindex)->magic == FBR_DINDEX_MAGIC);		\
}
#define fbr_dindex_bucket_ok(bucket)				\
{								\
	assert(bucket);						\
	assert((bucket)->magic == FBR_DINDEX_BUCKET_MAGIC);	\
}

RB_GENERATE_STATIC(fbr_dindex_tree, fbr_directory, dindex_entry, fbr_directory_cmp)

struct fbr_dindex *
fbr_dindex_alloc(void)
{
	struct fbr_dindex *dindex;

	dindex = calloc(1, sizeof(*dindex));
	assert(dindex);

	dindex->magic = FBR_DINDEX_MAGIC;

	for (size_t i = 0; i < FBR_DINDEX_BUCKET_COUNT; i++) {
		struct fbr_dindex_bucket *bucket = &dindex->buckets[i];

		bucket->magic = FBR_DINDEX_BUCKET_MAGIC;

		RB_INIT(&bucket->tree);
		assert_zero(pthread_rwlock_init(&bucket->rwlock, NULL));
	}

	return dindex;
}

static struct fbr_dindex_bucket *
_dindex_hash_djb2(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	const char *dirname = fbr_filename_get(&directory->dirname);
	assert(dirname);

        unsigned long hash = 5381;
        int c;

        while ((c = *dirname++)) {
                hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
        }

        struct fbr_dindex_bucket *bucket = &(dindex->buckets[hash % FBR_DINDEX_BUCKET_COUNT]);
	fbr_dindex_bucket_ok(bucket);

        return bucket;
}

void
fbr_dindex_add(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	struct fbr_dindex_bucket *bucket = _dindex_hash_djb2(dindex, directory);

	assert_zero(pthread_rwlock_wrlock(&bucket->rwlock));
	fbr_dindex_bucket_ok(bucket);

	assert(directory->state == FBR_DIRSTATE_NONE);

	directory->state = FBR_DIRSTATE_FETCH;

	// refcount starts at 1, that means we need something to release this
	directory->refcount = 1;

	// TODO we need a timestamp so we can age and release

	struct fbr_directory *existing = RB_INSERT(fbr_dindex_tree, &bucket->tree, directory);
	fbr_ASSERT(!existing, "TODO");

	assert_zero(pthread_rwlock_unlock(&bucket->rwlock));
}

struct fbr_directory *
_dindex_get(struct fbr_dindex *dindex, char *dirname, size_t dirname_len, int refcount)
{
	fbr_dindex_ok(dindex);
	assert(dirname);

	struct fbr_directory find;
	find.magic = FBR_DIRECTORY_MAGIC;
	find.dirname.layout = FBR_FILENAME_CONST;
	find.dirname.len = dirname_len;
	find.dirname.name_ptr = dirname;

        struct fbr_dindex_bucket *bucket = _dindex_hash_djb2(dindex, &find);

        assert_zero(pthread_rwlock_rdlock(&bucket->rwlock));
        fbr_dindex_bucket_ok(bucket);

        struct fbr_directory *directory = RB_FIND(fbr_dindex_tree, &bucket->tree, &find);

	if (directory) {
		fbr_directory_ok(directory);
		assert(directory->refcount);

		if (refcount) {
			directory->refcount++;
		}
	}

	assert_zero(pthread_rwlock_unlock(&bucket->rwlock));

	return directory;
}

struct fbr_directory *
fbr_dindex_get(struct fbr_dindex *dindex, char *dirname, size_t dirname_len)
{
	return _dindex_get(dindex, dirname, dirname_len, 1);
}

struct fbr_directory *
fbr_dindex_get_noref(struct fbr_dindex *dindex, char *dirname, size_t dirname_len)
{
	return _dindex_get(dindex, dirname, dirname_len, 0);
}

void
fbr_dindex_release(struct fbr_dindex *dindex, struct fbr_directory *directory)
{
	fbr_dindex_ok(dindex);
	fbr_directory_ok(directory);

	struct fbr_dindex_bucket *bucket = _dindex_hash_djb2(dindex, directory);

	assert_zero(pthread_rwlock_wrlock(&bucket->rwlock));
	fbr_dindex_bucket_ok(bucket);

	assert(directory->refcount);
	directory->refcount--;

	if (directory->refcount) {
		assert_zero(pthread_rwlock_unlock(&bucket->rwlock));
		return;
	}

	struct fbr_directory *ret = RB_REMOVE(fbr_dindex_tree, &bucket->tree, directory);
	assert(directory == ret);

	assert_zero(pthread_rwlock_unlock(&bucket->rwlock));

	fbr_directory_free(directory);
}

void
fbr_dindex_free(struct fbr_dindex *dindex)
{
	fbr_dindex_ok(dindex);

	for (size_t i = 0; i < FBR_DINDEX_BUCKET_COUNT; i++) {
		struct fbr_dindex_bucket *bucket = &dindex->buckets[i];
		fbr_dindex_bucket_ok(bucket);

		struct fbr_directory *directory, *next;

		RB_FOREACH_SAFE(directory, fbr_dindex_tree, &bucket->tree, next) {
			fbr_directory_ok(directory);

			struct fbr_directory *ret = RB_REMOVE(fbr_dindex_tree, &bucket->tree,
				directory);
			assert(directory == ret);

			fbr_directory_free(directory);
		}

		assert(RB_EMPTY(&bucket->tree));

		assert_zero(pthread_rwlock_destroy(&bucket->rwlock));

		fbr_ZERO(bucket);
	}

	fbr_ZERO(dindex);

	free(dindex);
}
