/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_ops.h"

RB_GENERATE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *
fbr_directory_root_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_directory *root = fbr_directory_alloc(fs, "", 0);
	fbr_directory_ok(root);

	return root;
}

struct fbr_directory *
fbr_directory_alloc(struct fbr_fs *fs, char *name, size_t name_len)
{
	fbr_fs_ok(fs);
	assert(name);

	struct fbr_directory *directory = fbr_inline_alloc(sizeof(*directory),
		offsetof(struct fbr_directory, dirname), name, name_len);
	assert_zero(strncmp(fbr_filename_get(&directory->dirname), name, name_len));

	directory->magic = FBR_DIRECTORY_MAGIC;

	assert_zero(pthread_mutex_init(&directory->cond_lock, NULL));
	assert_zero(pthread_cond_init(&directory->cond, NULL));
	TAILQ_INIT(&directory->file_list);
	RB_INIT(&directory->filename_tree);

	fbr_directory_ok(directory);

	if (!name_len) {
		directory->inode = 1;

		fbr_fs_set_root(fs, directory);
	} else {
		directory->inode = fbr_inode_gen(fs);
	}

	fbr_dindex_add(fs, directory);

	// TODO dup

	fbr_fs_stat_add(&fs->stats.directories);
	fbr_fs_stat_add(&fs->stats.directories_total);

	return directory;
}

int
fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2)
{
	fbr_directory_ok(d1);
	fbr_directory_ok(d2);

	return d1->inode - d2->inode;
}

void
fbr_directory_add(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);
	assert_zero(file->refcounts.dindex);
	assert_zero(file->refcounts.inode);

	// directory ownership
	file->refcounts.dindex = 1;

	fbr_fs_stat_add(&fs->stats.file_refs);

	TAILQ_INSERT_TAIL(&directory->file_list, file, file_entry);

	struct fbr_file *ret = RB_INSERT(fbr_filename_tree, &directory->filename_tree, file);
	assert_zero(ret);
}

void
fbr_directory_set_state(struct fbr_directory *directory, enum fbr_directory_state state)
{
	fbr_directory_ok(directory);
	assert(state == FBR_DIRSTATE_OK || state == FBR_DIRSTATE_ERROR);

	assert_zero(pthread_mutex_lock(&directory->cond_lock));

	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);

	directory->state = state;

	assert_zero(pthread_cond_broadcast(&directory->cond));

	assert_zero(pthread_mutex_unlock(&directory->cond_lock));
}

void
fbr_directory_wait_ok(struct fbr_directory *directory)
{
	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_LOADING);

	assert_zero(pthread_mutex_lock(&directory->cond_lock));

	while (directory->state == FBR_DIRSTATE_LOADING) {
		pthread_cond_wait(&directory->cond, &directory->cond_lock);
	}

	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_OK);

	assert_zero(pthread_mutex_unlock(&directory->cond_lock));
}

struct fbr_file *
fbr_directory_find(struct fbr_directory *directory, const char *filename)
{
	fbr_directory_ok(directory);
	assert(filename);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	fbr_ZERO(&find.filename);
	find.filename.layout = FBR_FILENAME_CONST;
	find.filename.len = strlen(filename);
	find.filename.cname_ptr = filename;

	struct fbr_file *file = RB_FIND(fbr_filename_tree, &directory->filename_tree, &find);

	if (!file) {
		return NULL;
	}

	fbr_file_ok(file);

	// directory owns a reference

	return file;
}

uint64_t
fbr_directory_to_fh(struct fbr_directory *directory)
{
	fbr_directory_ok(directory);

	return (uint64_t)directory;
}

struct fbr_directory *
fbr_directory_fh(uint64_t fh)
{
	struct fbr_directory *directory = (struct fbr_directory*)fh;
	fbr_directory_ok(directory);

	return directory;
}
