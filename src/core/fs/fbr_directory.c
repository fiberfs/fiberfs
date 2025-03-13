/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "core/fuse/fbr_fuse.h"
#include "core/store/fbr_store.h"

static const struct fbr_path_name _FBR_DIRNAME_ROOT = {0, ""};
const struct fbr_path_name *FBR_DIRNAME_ROOT = &_FBR_DIRNAME_ROOT;

RB_GENERATE(fbr_filename_tree, fbr_file, filename_entry, fbr_file_cmp)

struct fbr_directory *
fbr_directory_root_alloc(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);

	if (!root_file) {
		fbr_fs_LOCK(fs);

		root_file = fbr_inode_take(fs, FBR_INODE_ROOT);

		if (!root_file) {
			assert_zero(fs->root_file);

			// TODO mode needs to be configurable
			root_file = fbr_file_alloc(fs, NULL, PATH_NAME_EMPTY, S_IFDIR | 0755);
			fbr_file_ok(root_file);
			assert_dev(root_file->inode == FBR_INODE_ROOT);

			fbr_inode_add(fs, root_file);

			fs->root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
			fbr_file_ok(root_file);
		}

		fbr_fs_UNLOCK(fs);
	}

	struct fbr_directory *root = fbr_directory_alloc(fs, FBR_DIRNAME_ROOT, root_file->inode);
	fbr_directory_ok(root);
	assert_dev(root->inode == FBR_INODE_ROOT);

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

	pt_assert(pthread_cond_init(&directory->update, NULL));
	TAILQ_INIT(&directory->file_list);
	RB_INIT(&directory->filename_tree);

	if (directory->inode == FBR_INODE_ROOT) {
		assert_zero_dev(dirname->len);
	} else {
		assert_dev(dirname->len);
	}

	fbr_directory_ok(directory);

	fbr_fs_stat_add(&fs->stats.directories);
	fbr_fs_stat_add(&fs->stats.directories_total);

	while (1) {
		struct fbr_directory *inserted = fbr_dindex_add(fs, directory);
		fbr_directory_ok(inserted);

		if (inserted == directory) {
			assert(directory->state == FBR_DIRSTATE_LOADING);

			directory->file = fbr_inode_take(fs, directory->inode);
			fbr_file_ok(directory->file);

			break;
		}

		if (inserted->state == FBR_DIRSTATE_LOADING) {
			fbr_directory_wait_ok(fs, inserted);
		}

		if (inserted->state == FBR_DIRSTATE_OK) {
			assert(directory->state == FBR_DIRSTATE_NONE);
			fbr_directory_free(fs, directory);

			return inserted;
		}

		assert_dev(inserted->state == FBR_DIRSTATE_ERROR);

		fbr_dindex_release(fs, &inserted);
	}

	return directory;
}

void
fbr_directory_free(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->refcounts.in_dindex);
	assert_zero(directory->refcounts.in_lru);

	if (directory->state == FBR_DIRSTATE_OK) {
		fbr_directory_expire(fs, directory, NULL);
	}

	struct fbr_file *file, *temp;

	TAILQ_FOREACH_SAFE(file, &directory->file_list, file_entry, temp) {
		fbr_file_ok(file);

		TAILQ_REMOVE(&directory->file_list, file, file_entry);

		(void)RB_REMOVE(fbr_filename_tree, &directory->filename_tree, file);

		fbr_file_release_dindex(fs, &file);
		assert_zero_dev(file);

		directory->file_count--;
	}

	if (directory->file) {
		fbr_inode_release(fs, &directory->file);
		assert_zero_dev(directory->file);
	}

	assert(TAILQ_EMPTY(&directory->file_list));
	assert(RB_EMPTY(&directory->filename_tree));
	assert_zero(directory->file_count);

	pt_assert(pthread_cond_destroy(&directory->update));

	fbr_path_free(&directory->dirname);

	fbr_ZERO(directory);

	free(directory);

	fbr_fs_stat_sub(&fs->stats.directories);
}

int
fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2)
{
	fbr_directory_ok(d1);
	fbr_directory_ok(d2);

	return fbr_path_cmp_dir(&d1->dirname, &d2->dirname);
}

void
fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);
	assert_zero_dev(file->refcounts.dindex);
	assert_zero_dev(file->refcounts.inode);

	// directory ownership
	file->refcounts.dindex = 1;

	fbr_fs_stat_add(&fs->stats.file_refs);

	file->parent_inode = directory->inode;

	TAILQ_INSERT_TAIL(&directory->file_list, file, file_entry);

	struct fbr_file *ret = RB_INSERT(fbr_filename_tree, &directory->filename_tree, file);
	fbr_ASSERT(!ret, "duplicate file added to directory");

	directory->file_count++;
}

struct fbr_file *
fbr_directory_find_file(struct fbr_directory *directory, const char *filename,
    size_t filename_len)
{
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);
	assert(filename);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	fbr_path_init_file(&find.path, filename, filename_len);

	struct fbr_file *file = RB_FIND(fbr_filename_tree, &directory->filename_tree, &find);

	if (!file) {
		return NULL;
	}

	fbr_file_ok(file);

	// directory owns a reference

	return file;
}

void
fbr_directory_expire(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_directory *new_directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->state == FBR_DIRSTATE_OK);
	assert_zero(directory->previous);

	if (new_directory) {
		fbr_directory_ok(new_directory);
		assert(new_directory->state == FBR_DIRSTATE_OK);
	}

	if (fs->shutdown || directory->expired) {
		return;
	}

	// If we have a TTL, files can never be forced to expire
	if (fs->config.dentry_ttl > 0 && !new_directory) {
		return;
	}

	directory->expired = 1;

	struct fbr_path_name dirname;
	fbr_path_get_dir(&directory->dirname, &dirname);

	assert_dev(fs->log);
	if (new_directory) {
		fs->log("** DIR_EXP inode: %lu(%lu) refcount: %u+%u+%u path: '%.*s':%zu"
				" new: true new_inode: %lu(%lu)",
			directory->inode, directory->version,
			directory->refcounts.in_dindex,
				directory->refcounts.in_lru,
				directory->refcounts.fs,
			(int)dirname.len, dirname.name, dirname.len,
			new_directory->inode, new_directory->version);
	} else {
		fs->log("** DIR_EXP inode: %lu(%lu) refcount: %u+%u+%u path: '%.*s':%zu"
				" new: false",
			directory->inode, directory->version,
			directory->refcounts.in_dindex,
				directory->refcounts.in_lru,
				directory->refcounts.fs,
			(int)dirname.len, dirname.name, dirname.len);
	}

	if (!fs->fuse_ctx) {
		return;
	}

	fbr_fuse_context_ok(fs->fuse_ctx);
	assert(fs->fuse_ctx->session);

	struct fbr_file *file;

	TAILQ_FOREACH(file, &directory->file_list, file_entry) {
		fbr_file_ok(file);

		if (!file->refcounts.inode) {
			continue;
		}

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		struct fbr_file *new_file = NULL;
		int file_deleted = 0;
		int file_expired = 0;

		if (new_directory) {
			new_file = fbr_directory_find_file(new_directory, filename.name,
				filename.len);

			if (!new_file) {
				file_deleted = 1;
			} else if (file->inode != new_file->inode) {
				assert_dev(file->version != new_file->version);
				file_expired = 1;
			}
		} else {
			assert_dev(fs->config.dentry_ttl <= 0);
			file_expired = 1;
		}

		int ret;

		if (file_deleted) {
			fs->log("** FILE_DELETE inode: %lu", file->inode);

			ret = fuse_lowlevel_notify_delete(fs->fuse_ctx->session, directory->inode,
				file->inode, filename.name, filename.len);
			assert_dev(ret != -ENOSYS);
			(void)ret;
		} else if (file_expired) {
			fs->log("** FILE_EXP inode: %lu", file->inode);

			ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session,
				directory->inode, filename.name, filename.len);
			assert_dev(ret != -ENOSYS);
			(void)ret;
		}
	}
}
