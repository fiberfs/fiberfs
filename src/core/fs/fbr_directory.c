/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "core/fuse/fbr_fuse.h"

static const struct fbr_path_name _FBR_DIRNAME_ROOT = {0, ""};
const struct fbr_path_name *FBR_DIRNAME_ROOT = &_FBR_DIRNAME_ROOT;

RB_GENERATE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *
fbr_directory_root_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);
	assert_zero(fs->root);

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);

	if (!root_file) {
		// TODO mode needs to be configurable
		root_file = fbr_file_alloc(fs, NULL, PATH_NAME_EMPTY, S_IFDIR | 0755);
		fbr_file_ok(root_file);
		assert_dev(root_file->inode == FBR_INODE_ROOT);

		fbr_inode_add(fs, root_file);

		// Pull a hidden ref so this inode never disappears
		//(void)fbr_inode_take(fs, FBR_INODE_ROOT);
	}

	struct fbr_directory *root = fbr_directory_alloc(fs, FBR_DIRNAME_ROOT, root_file->inode);
	fbr_directory_ok(root);
	assert_dev(root->inode == FBR_INODE_ROOT);

	fbr_fs_set_root(fs, root);

	fbr_inode_release(fs, &root_file);
	assert_zero_dev(root_file);

	return root;
}

struct fbr_directory *
fbr_directory_alloc(struct fbr_fs *fs, const struct fbr_path_name *dirname, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(dirname);

	struct fbr_directory *directory = fbr_path_storage_alloc(sizeof(*directory),
		offsetof(struct fbr_directory, dirname), dirname, PATH_NAME_EMPTY);
	assert_dev(directory);

	directory->magic = FBR_DIRECTORY_MAGIC;
	directory->inode = inode;

	assert_zero(pthread_mutex_init(&directory->cond_lock, NULL));
	assert_zero(pthread_cond_init(&directory->cond, NULL));
	TAILQ_INIT(&directory->file_list);
	RB_INIT(&directory->filename_tree);

	if (directory->inode == FBR_INODE_ROOT) {
		assert_zero(fs->root);
		assert_zero(dirname->len);
	} else {
		assert(dirname->len);
	}

	directory->file = fbr_inode_take(fs, directory->inode);

	fbr_directory_ok(directory);
	fbr_file_ok(directory->file);

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

	return fbr_path_cmp_dir(&d1->dirname, &d1->dirname);
}

void
fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);

	// directory ownership
	file->refcounts.dindex = 1;

	fbr_fs_stat_add(&fs->stats.file_refs);

	file->parent_inode = directory->inode;

	TAILQ_INSERT_TAIL(&directory->file_list, file, file_entry);

	struct fbr_file *ret = RB_INSERT(fbr_filename_tree, &directory->filename_tree, file);
	fbr_ASSERT(!ret, "duplicate file added to directory");
}

void
fbr_directory_set_state(struct fbr_directory *directory, enum fbr_directory_state state)
{
	fbr_directory_ok(directory);
	assert(state == FBR_DIRSTATE_OK || state == FBR_DIRSTATE_ERROR);

	assert_zero(pthread_mutex_lock(&directory->cond_lock));

	fbr_directory_ok(directory);
	assert(directory->state < FBR_DIRSTATE_OK);

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

	while (directory->state < FBR_DIRSTATE_OK) {
		pthread_cond_wait(&directory->cond, &directory->cond_lock);
	}

	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_OK);

	assert_zero(pthread_mutex_unlock(&directory->cond_lock));
}

struct fbr_file *
fbr_directory_find_file(struct fbr_directory *directory, const char *filename)
{
	fbr_directory_ok(directory);
	assert(filename);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	fbr_path_init_file(&find.path, filename, strlen(filename));

	struct fbr_file *file = RB_FIND(fbr_filename_tree, &directory->filename_tree, &find);

	if (!file) {
		return NULL;
	}

	fbr_file_ok(file);

	// directory owns a reference

	return file;
}
