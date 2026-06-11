/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "config/fbr_config.h"
#include "core/fuse/fbr_fuse.h"
#include "core/store/fbr_store.h"
#include "data/queue.h"
#include "data/tree.h"

static const struct fbr_path_name _FBR_DIRNAME_ROOT = {0, ""};
const struct fbr_path_name *FBR_DIRNAME_ROOT = &_FBR_DIRNAME_ROOT;

RB_GENERATE(fbr_filename_tree, fbr_file_ptr, filename_entry, fbr_file_ptr_cmp)

static void _directory_expire(struct fbr_fs *fs, struct fbr_directory *directory);

void
fbr_directory_root_inode_init(struct fbr_fs *fs)
{
	assert_dev(fs);

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);

	if (!root_file) {
		fbr_fs_LOCK(fs);

		root_file = fbr_inode_take(fs, FBR_INODE_ROOT);

		if (!root_file) {
			assert_zero(fs->root_file);

			root_file = fbr_file_alloc(fs, NULL, FBR_DIRNAME_ROOT);
			fbr_file_ok(root_file);
			assert_dev(root_file->inode == FBR_INODE_ROOT);
			assert_dev(root_file->state == FBR_FILE_OK);

			unsigned long umode = fbr_conf_get_ulong("FS_ROOT_MODE", 755);
			unsigned int mode = fbr_ulong2octal(umode);

			unsigned int uid = fbr_conf_get_ulong("FS_ROOT_UID", getuid());
			unsigned int gid = fbr_conf_get_ulong("FS_ROOT_GID", getgid());

			root_file->mode = S_IFDIR | mode;
			root_file->uid = uid;
			root_file->gid = gid;

			fbr_inode_add(fs, root_file);

			fs->root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
			fbr_file_ok(fs->root_file);
		}

		fbr_fs_UNLOCK(fs);
	}

	assert_dev(fs->root_file);

	fbr_inode_release(fs, &root_file);
	assert_zero_dev(root_file);
}

static void
_directory_init(struct fbr_fs *fs, struct fbr_directory *directory, fbr_inode_t inode)
{
	assert_dev(fs);
	assert_dev(directory);
	assert_dev(inode >= FBR_INODE_ROOT);

	directory->magic = FBR_DIRECTORY_MAGIC;
	directory->inode = inode;

	pt_assert(pthread_cond_init(&directory->update, NULL));
	RB_INIT(&directory->filename_tree);

	fbr_directory_ok(directory);

	fbr_stat_add(&fs->stats.directories);
	fbr_stat_add(&fs->stats.directories_total);
}

struct fbr_directory *
fbr_directory_alloc(struct fbr_fs *fs, const struct fbr_path_name *dirpath, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(dirpath);

	if (inode == FBR_INODE_ROOT) {
		assert_zero_dev(dirpath->length);
		fbr_directory_root_inode_init(fs);
	} else {
		assert_dev(dirpath->length);
	}

	struct fbr_directory *directory = calloc(1, sizeof(*directory));
	assert_dev(directory);

	_directory_init(fs, directory, inode);

	directory->path = fbr_path_shared_alloc(dirpath);
	assert_dev(directory->path);

	while (directory->state == FBR_DIRSTATE_NONE) {
		struct fbr_directory *inserted = fbr_dindex_add(fs, directory);
		fbr_directory_ok(inserted);

		if (inserted == directory) {
			// Insert success, allow caller to begin loading
			if (directory->state == FBR_DIRSTATE_LOADING) {
				directory->file = fbr_inode_take(fs, directory->inode);
				fbr_file_ok(directory->file);

				if (fbr_is_dev()) {
					struct fbr_fullpath_name filename;
					fbr_path_get_full(&directory->file->path, &filename);
					assert_zero(fbr_path_name_cmp(dirpath, &filename.path));
				}
			} else {
				// Inode is too old, caller gets an error state
				assert_dev(inserted->state == FBR_DIRSTATE_ERROR);
			}

			break;
		}

		// We got someone elses insertion
		assert(directory->state == FBR_DIRSTATE_NONE);

		if (inserted->state == FBR_DIRSTATE_LOADING) {
			fbr_directory_wait_ok(fs, inserted);
		}

		int newer = fbr_directory_new_cmp(directory, inserted);
		assert_dev(newer >= 0);

		if (inserted->state == FBR_DIRSTATE_OK) {
			// The insertion inodes are equal, return an ok directory
			if (!newer) {
				fbr_directory_free(fs, directory);
				fbr_stat_add(&fs->stats.dir_alloc_hit);
				return inserted;
			}
		} else {
			// Someone elses insertion failed
			assert_dev(inserted->state == FBR_DIRSTATE_ERROR);
		}

		fbr_dindex_release(fs, &inserted);

		fbr_stat_add(&fs->stats.dir_alloc_miss);

		// Try the insertion again, we have the newest inode right now
	}

	assert_dev(directory->state >= FBR_DIRSTATE_LOADING);

	return directory;
}

struct fbr_directory *
fbr_directory_root_alloc(struct fbr_fs *fs)
{
	return fbr_directory_alloc(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT);
}

struct fbr_directory *
fbr_directory_load(struct fbr_fs *fs, const struct fbr_path_name *dirname, fbr_inode_t inode,
    int route_s3)
{
	fbr_fs_ok(fs);
	assert(dirname);
	assert(inode);

	struct fbr_fs_timeout timeout;
	fbr_fs_timeout_init(&timeout);

	struct fbr_directory *directory = NULL;
	struct fbr_directory *previous = NULL;

	while (!directory) {
		directory = fbr_directory_alloc(fs, dirname, inode);
		fbr_directory_ok(directory);

		if (route_s3 && directory->state == FBR_DIRSTATE_OK) {
			fbr_dindex_release(fs, &directory);

			if (fbr_fs_is_timeout(fs, &timeout)) {
				return NULL;
			}
		}
	}

	if (directory->state == FBR_DIRSTATE_LOADING) {
		previous = directory->previous;
		if (previous) {
			assert_dev(previous->state == FBR_DIRSTATE_OK);
			fbr_dindex_ref(fs, previous);
		}

		fbr_index_read(fs, directory, &timeout, route_s3);
	}

	if (directory->state == FBR_DIRSTATE_ERROR) {
		fbr_dindex_release(fs, &directory);
		return previous;
	}

	fbr_ASSERT(directory->state == FBR_DIRSTATE_OK,
		"fbr_directory_load() directory->state: %d", directory->state);

	if (previous) {
		fbr_dindex_release(fs, &previous);
	}

	return directory;
}

// NOTE: Always free after replying to fuse
// This can call fuse_lowlevel_notify_inval_entry() on expiration
// See: https://libfuse.github.io/doxygen/fuse__lowlevel_8h.html#ab14032b74b0a57a2b3155dd6ba8d6095
void
fbr_directory_free(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert_zero(directory->refcounts.in_dindex);
	assert_zero(directory->refcounts.in_lru);

	if (directory->state == FBR_DIRSTATE_OK) {
		_directory_expire(fs, directory);
	}

	assert_zero_dev(directory->next);

	struct fbr_file_ptr *file_ptr, *temp;
	RB_FOREACH_SAFE(file_ptr, fbr_filename_tree, &directory->filename_tree, temp) {
		fbr_file_ptr_ok(file_ptr);
		struct fbr_file *file = file_ptr->file;

		(void)RB_REMOVE(fbr_filename_tree, &directory->filename_tree, file_ptr);
		fbr_file_ptr_free(file_ptr);

		fbr_file_release_dindex(fs, &file);
		assert_zero_dev(file);

		directory->file_count--;
	}

	if (directory->file) {
		fbr_inode_release(fs, &directory->file);
		assert_zero_dev(directory->file);
	}

	assert(RB_EMPTY(&directory->filename_tree));
	assert_zero(directory->file_count);

	pt_assert(pthread_cond_destroy(&directory->update));
	fbr_path_shared_release(directory->path);

	fbr_zero(directory);
	free(directory);

	fbr_stat_sub(&fs->stats.directories);
}

void
fbr_directory_name(const struct fbr_directory *directory, struct fbr_path_name *result)
{
	fbr_directory_ok(directory);
	assert(result);

	fbr_path_shared_name(directory->path, result);
}

int
fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2)
{
	fbr_directory_ok(d1);
	fbr_directory_ok(d2);

	return fbr_path_shared_cmp(d1->path, d2->path);
}

int
fbr_directory_new_cmp(const struct fbr_directory *left, const struct fbr_directory *right)
{
	fbr_directory_ok(left);
	fbr_directory_ok(right);

	if (left->inode > right->inode) {
		return 1;
	} else if (left->inode < right->inode) {
		return -1;
	}

	return 0;
}

void
fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);

	fbr_file_ref_dindex(fs, file);

	struct fbr_file_ptr *file_ptr = fbr_file_ptr_get(fs, directory, file);
	fbr_file_ptr_ok(file_ptr);

	file_ptr = RB_INSERT(fbr_filename_tree, &directory->filename_tree, file_ptr);
	fbr_ASSERT(!file_ptr, "duplicate file added to directory");

	directory->file_count++;
}

void
fbr_directory_remove_file(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);

	struct fbr_file_ptr *file_ptr, *temp;
	RB_FOREACH_SAFE(file_ptr, fbr_filename_tree, &directory->filename_tree, temp) {
		fbr_file_ptr_ok(file_ptr);

		if (file_ptr->file != file) {
			continue;
		}

		(void)RB_REMOVE(fbr_filename_tree, &directory->filename_tree, file_ptr);
		fbr_file_ptr_free(file_ptr);

		fbr_file_release_dindex(fs, &file);

		directory->file_count--;

		return;
	}

	fbr_ABORT("fbr_directory_remove_file() file not found");
}

struct fbr_file *
fbr_directory_find_file(struct fbr_directory *directory, const char *filename,
    size_t filename_len)
{
	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_LOADING);
	assert(directory->state != FBR_DIRSTATE_ERROR);
	assert(filename);

	struct fbr_file find;
	find.magic = FBR_FILE_MAGIC;
	fbr_path_init_file(&find.path, filename, filename_len);
	struct fbr_file_ptr find_ptr;
	find_ptr.file = &find;

	struct fbr_file_ptr *file_ptr = RB_FIND(fbr_filename_tree, &directory->filename_tree,
		&find_ptr);

	if (!file_ptr) {
		return NULL;
	}

	struct fbr_file *file = file_ptr->file;
	fbr_file_ok(file);
	assert_dev(file->state >= FBR_FILE_OK);

	// directory owns a reference

	return file;
}

static void
_directory_expire(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->state == FBR_DIRSTATE_OK);
	assert_zero_dev(directory->previous);

	struct fbr_directory *next = directory->next;

	if (next) {
		fbr_directory_ok(next);
		assert(next->state == FBR_DIRSTATE_OK);
	}

	if (fs->shutdown || directory->expired) {
		if (next) {
			fbr_dindex_release(fs, &directory->next);
		}
		return;
	}

	// If we have a TTL, files can never be forced to expire
	if (fs->config.dentry_ttl > 0) {
		assert_zero_dev(next);
		return;
	}

	directory->expired = 1;

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);

	if (next) {
		fbr_rlog(FBR_LOG_DIR_EXP, "inode: %lu(%lu) refcount: %u+%u+%u path: '%.*s':%zu"
				" next: true next_inode: %lu(%lu)",
			directory->inode, directory->generation,
			directory->refcounts.in_dindex,
				directory->refcounts.in_lru,
				directory->refcounts.fs,
			(int)dirname.length, dirname.name, dirname.length,
			next->inode, next->generation);
	} else {
		fbr_rlog(FBR_LOG_DIR_EXP, "inode: %lu(%lu) refcount: %u+%u+%u path: '%.*s':%zu"
				" next: false",
			directory->inode, directory->generation,
			directory->refcounts.in_dindex,
				directory->refcounts.in_lru,
				directory->refcounts.fs,
			(int)dirname.length, dirname.name, dirname.length);
	}

	if (!fs->fuse_ctx) {
		if (next) {
			fbr_dindex_release(fs, &directory->next);
		}
		return;
	}

	fbr_fuse_context_ok(fs->fuse_ctx);
	assert(fs->fuse_ctx->session);

	if (next && next->remote) {
		fbr_rlog(FBR_LOG_DIR_EXP, "INVAL inode: %lu (directory)", directory->inode);
		int ret = fuse_lowlevel_notify_inval_inode(fs->fuse_ctx->session, directory->inode,
			0, 0);
		assert_dev(ret != -ENOSYS);
	}

	struct fbr_file_ptr *file_ptr;
	RB_FOREACH(file_ptr, fbr_filename_tree, &directory->filename_tree) {
		fbr_file_ptr_ok(file_ptr);
		struct fbr_file *file = file_ptr->file;

		if (!file->refcounts.inode) {
			continue;
		}

		struct fbr_path_name filename;
		fbr_path_get_file(&file->path, &filename);

		struct fbr_file *new_file = NULL;
		int file_deleted = 0;
		int file_expired = 0;
		int file_inval = 0;
		int ret;

		if (next) {
			new_file = fbr_directory_find_file(next, filename.name, filename.length);

			if (!new_file) {
				file_deleted = 1;
			} else if (file->inode != new_file->inode) {
				file_expired = 1;
			}
		} else {
			file_inval = 1;
		}

		if (file_deleted) {
			fbr_rlog(FBR_LOG_DIR_EXP, "DELETE inode: %lu (file)", file->inode);

			file->state = FBR_FILE_EXPIRED;

			ret = fuse_lowlevel_notify_delete(fs->fuse_ctx->session, directory->inode,
				file->inode, filename.name, filename.length);
			assert_dev(ret != -ENOSYS);
		} else if (file_expired || file_inval) {
			fbr_rlog(FBR_LOG_DIR_EXP, "INVAL inode: %lu (file)", file->inode);

			if (file_expired) {
				file->state = FBR_FILE_EXPIRED;
			}

			ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session,
				directory->inode, filename.name, filename.length);
			assert_dev(ret != -ENOSYS);
		}
	}

	if (next) {
		fbr_dindex_release(fs, &directory->next);
	}
}

void
fbr_directory_copy(struct fbr_fs *fs, struct fbr_directory *dest, struct fbr_directory *source)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(dest);
	assert(dest->state == FBR_DIRSTATE_LOADING);
	assert_zero(dest->file_count);
	assert_dev(RB_EMPTY(&dest->filename_tree));
	fbr_directory_ok(source);
	assert(source->state == FBR_DIRSTATE_OK);
	assert_zero_dev(source->expired);

	dest->generation = source->generation;

	struct fbr_file_ptr *file_ptr;
	RB_FOREACH(file_ptr, fbr_filename_tree, &source->filename_tree) {
		fbr_file_ptr_ok(file_ptr);
		struct fbr_file *file = file_ptr->file;

		fbr_directory_add_file(fs, dest, file);
	}

	assert_dev(dest->file_count == source->file_count);
}

void
fbr_directory_clone_id(struct fbr_fs *fs, struct fbr_directory *dest, struct fbr_directory *source)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(dest);
	assert(dest->state == FBR_DIRSTATE_LOADING);
	fbr_directory_ok(source);
	assert(source->state == FBR_DIRSTATE_OK);
	assert_dev(source->version);
	assert_dev(source->generation);

	dest->version = source->version;
	dest->generation = source->generation;
}

int
fbr_directory_stale(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->state == FBR_DIRSTATE_OK);

	double now = fbr_get_time();

	double dir_time = directory->updated +
		(fs->config.root_ttl_sec ? fs->config.root_ttl_sec : FBR_ROOT_TTL_MIN);

	if (dir_time < now) {
		return 1;
	}

	return 0;
}

struct fbr_directory *
fbr_directory_get(struct fbr_fs *fs, const struct fbr_path_name *dirpath, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(dirpath);
	assert(inode);

	struct fbr_directory *directory = fbr_dindex_take(fs, dirpath, 0);

	if (directory) {
		fbr_directory_ok(directory);

		if (directory->state == FBR_DIRSTATE_ERROR) {
			fbr_dindex_release(fs, &directory);
		} else if (fbr_directory_stale(fs, directory)) {
			fbr_rlog(FBR_LOG_FS, "stale directory found");
			fbr_dindex_release(fs, &directory);
		} else if (directory->inode < inode) {
			fbr_rlog(FBR_LOG_FS, "directory inode too old (%lu < %lu)",
				directory->inode, inode);
			fbr_dindex_release(fs, &directory);
		}
	}

	if (!directory) {
		directory = fbr_directory_load(fs, dirpath, inode, 0);
		if (!directory) {
			return NULL;
		}
	}

	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);

	fbr_rlog(FBR_LOG_FS, "directory found: '%s' (inode: %lu)", dirpath->name, inode);

	return directory;
}

struct fbr_directory *
fbr_directory_from_inode(struct fbr_fs *fs, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(inode);

	struct fbr_file *file = fbr_inode_take(fs, inode);
	if (!file) {
		fbr_rlog(FBR_LOG_FS, "directory inode: %lu not found", inode);
		return NULL;
	}
	assert_dev(file->inode == inode);

	if (file->state == FBR_FILE_EXPIRED) {
		fbr_rlog(FBR_LOG_FS, "directory inode: %lu expired", inode);
		fbr_inode_release(fs, &file);
		return NULL;
	} else if (!S_ISDIR(file->mode)) {
		fbr_rlog(FBR_LOG_FS, "directory inode: %lu not a directory", inode);
		fbr_inode_release(fs, &file);
		return NULL;
	}

	struct fbr_fullpath_name dirpath;
	fbr_path_get_full(&file->path, &dirpath);

	fbr_inode_release(fs, &file);

	struct fbr_directory *directory = fbr_directory_get(fs, &dirpath.path, inode);
	if (!directory) {
		return NULL;
	} else if (directory->inode > inode) {
		fbr_rlog(FBR_LOG_FS, "directory inode too new (%lu < %lu) return ERROR",
			directory->inode, inode);
		fbr_dindex_release(fs, &directory);
		return NULL;
	}

	assert_dev(directory->inode == inode);

	return directory;
}
