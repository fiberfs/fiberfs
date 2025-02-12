/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_ops.h"

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

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	struct fbr_directory *directory = calloc(1, sizeof(*directory) + inline_len);
	fbr_fuse_ASSERT(directory, NULL);

	if (inline_len) {
		inline_ptr = (char*)directory + sizeof(*directory);
	}

	directory->magic = FBR_DIRECTORY_MAGIC;

	fbr_filename_init(&directory->dirname, inline_ptr, name, name_len);

	assert_zero(pthread_mutex_init(&directory->cond_lock, NULL));
	assert_zero(pthread_cond_init(&directory->cond, NULL));
	TAILQ_INIT(&directory->file_list);
	RB_INIT(&directory->filename_tree);

	fbr_directory_ok(directory);

	if (!name_len) {
		directory->inode = 1;

		fbr_fs_set_root(fs, directory);
	} else {
		directory->inode = fbr_inode_gen(fs->inode);
	}

	fbr_dindex_add(fs->dindex, directory);

	// TODO dup

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
fbr_directory_add(struct fbr_directory *directory, struct fbr_file *file)
{
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);
	assert_zero(file->refcount);

	// directory ownership
	file->refcount = 1;

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
