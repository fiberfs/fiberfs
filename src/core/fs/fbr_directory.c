/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "core/fuse/fbr_fuse.h"
#include "core/store/fbr_store.h"

static const struct fbr_path_name _FBR_DIRNAME_ROOT = {0, ""};
const struct fbr_path_name *FBR_DIRNAME_ROOT = &_FBR_DIRNAME_ROOT;

RB_GENERATE(fbr_filename_tree, fbr_file_ptr, filename_entry, fbr_file_ptr_cmp)

static void _directory_expire(struct fbr_fs *fs, struct fbr_directory *directory);

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

			root_file = fbr_file_alloc(fs, NULL, FBR_DIRNAME_ROOT);
			fbr_file_ok(root_file);
			assert_dev(root_file->inode == FBR_INODE_ROOT);
			assert_dev(root_file->state == FBR_FILE_OK);

			// TODO mode needs to be configurable
			root_file->mode = S_IFDIR | 0755;
			root_file->uid = getuid();
			root_file->gid = getgid();

			fbr_inode_add(fs, root_file);

			fs->root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
			fbr_file_ok(root_file);
		}

		fbr_fs_UNLOCK(fs);
	}

	assert_dev(fs->root_file);

	struct fbr_directory *root = fbr_directory_alloc(fs, FBR_DIRNAME_ROOT, root_file->inode);
	fbr_directory_ok(root);
	assert_dev(root->inode == FBR_INODE_ROOT);

	fbr_inode_release(fs, &root_file);
	assert_zero_dev(root_file);

	return root;
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

	fbr_fs_stat_add(&fs->stats.directories);
	fbr_fs_stat_add(&fs->stats.directories_total);
}

struct fbr_directory *
fbr_directory_alloc(struct fbr_fs *fs, const struct fbr_path_name *dirname, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(dirname);

	if (inode == FBR_INODE_ROOT) {
		assert_zero_dev(dirname->len);
	} else {
		assert_dev(dirname->len);
	}

	struct fbr_directory *directory = calloc(1, sizeof(*directory));
	assert_dev(directory);

	_directory_init(fs, directory, inode);

	directory->path = fbr_path_shared_alloc(dirname);
	assert_dev(directory->path);

	while (directory->state == FBR_DIRSTATE_NONE) {
		struct fbr_directory *inserted = fbr_dindex_add(fs, directory);
		fbr_directory_ok(inserted);

		if (inserted == directory) {
			// Insert success, allow caller to begin loading
			if (directory->state == FBR_DIRSTATE_LOADING) {
				directory->file = fbr_inode_take(fs, directory->inode);
				fbr_file_ok(directory->file);

				if (fbr_assert_is_dev()) {
					struct fbr_path_name filename;
					char buf[PATH_MAX];
					fbr_path_get_full(&directory->file->path, &filename,
						buf, sizeof(buf));
					assert_zero(fbr_path_name_cmp(dirname, &filename));
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
				return inserted;
			}
		} else {
			// Someone elses insertion failed
			assert_dev(inserted->state == FBR_DIRSTATE_ERROR);
		}

		fbr_dindex_release(fs, &inserted);

		// Try the insertion again, we have the newest inode right now
	}

	assert_dev(directory->state >= FBR_DIRSTATE_LOADING);

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
		_directory_expire(fs, directory);
	}

	assert_zero_dev(directory->previous);
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

	fbr_ZERO(directory);
	free(directory);

	fbr_fs_stat_sub(&fs->stats.directories);
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
fbr_directory_add_file(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	fbr_file_ok(file);

	fbr_file_ref_dindex(fs, file);

	struct fbr_file_ptr *file_ptr = fbr_file_ptr_get(fs, file);
	fbr_file_ptr_ok(file_ptr);

	file_ptr = RB_INSERT(fbr_filename_tree, &directory->filename_tree, file_ptr);
	fbr_ASSERT(!file_ptr, "duplicate file added to directory");

	directory->file_count++;
}

struct fbr_file *
fbr_directory_find_file(struct fbr_directory *directory, const char *filename,
    size_t filename_len)
{
	fbr_directory_ok(directory);
	assert(directory->state >= FBR_DIRSTATE_LOADING);
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
	assert_zero(directory->previous);

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

	assert_dev(fs->logger);
	if (next) {
		fs->log("** DIR_EXP inode: %lu(%lu) refcount: %u+%u+%u path: '%.*s':%zu"
				" next: true next_inode: %lu(%lu)",
			directory->inode, directory->generation,
			directory->refcounts.in_dindex,
				directory->refcounts.in_lru,
				directory->refcounts.fs,
			(int)dirname.len, dirname.name, dirname.len,
			next->inode, next->generation);
	} else {
		fs->log("** DIR_EXP inode: %lu(%lu) refcount: %u+%u+%u path: '%.*s':%zu"
				" next: false",
			directory->inode, directory->generation,
			directory->refcounts.in_dindex,
				directory->refcounts.in_lru,
				directory->refcounts.fs,
			(int)dirname.len, dirname.name, dirname.len);
	}

	if (!fs->fuse_ctx) {
		if (next) {
			fbr_dindex_release(fs, &directory->next);
		}
		return;
	}

	fbr_fuse_context_ok(fs->fuse_ctx);
	assert(fs->fuse_ctx->session);

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

		if (next) {
			new_file = fbr_directory_find_file(next, filename.name,
				filename.len);

			if (!new_file) {
				file_deleted = 1;
			} else if (file->inode != new_file->inode) {
				assert_dev(file->generation != new_file->generation);
				file_expired = 1;
			}
		} else {
			file_expired = 1;
		}

		int ret;

		if (file_deleted) {
			fs->log("** FILE_DELETE inode: %lu", file->inode);

			file->state = FBR_FILE_EXPIRED;

			ret = fuse_lowlevel_notify_delete(fs->fuse_ctx->session, directory->inode,
				file->inode, filename.name, filename.len);
			assert_dev(ret != -ENOSYS);
		} else if (file_expired) {
			fs->log("** FILE_EXP inode: %lu", file->inode);

			file->state = FBR_FILE_EXPIRED;

			ret = fuse_lowlevel_notify_inval_entry(fs->fuse_ctx->session,
				directory->inode, filename.name, filename.len);
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
	assert(source->state >= FBR_DIRSTATE_LOADING);
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

struct fbr_directory *
_directory_get_loading(struct fbr_fs *fs, struct fbr_path_name *dirname, fbr_inode_t inode,
    struct fbr_directory **previous, unsigned int *attempts, double time_start)
{
	assert_dev(fs);
	assert_dev(dirname);
	assert_dev(inode);
	assert_dev(attempts);

	struct fbr_directory *directory = NULL;

	while (!directory) {
		directory = fbr_directory_alloc(fs, dirname, inode);
		fbr_directory_ok(directory);

		switch (directory->state) {
			case FBR_DIRSTATE_ERROR:
				// inode is stale, a top level change was made
				fbr_dindex_release(fs, &directory);
				return NULL;
			case FBR_DIRSTATE_OK:
				if (previous) {
					if (*previous) {
						fbr_dindex_release(fs, previous);
					}
					*previous = directory;
					directory = NULL;
				} else {
					fbr_dindex_release(fs, &directory);
				}
			case FBR_DIRSTATE_LOADING:
				continue;
			default:
				fbr_ABORT("FLUSH bad directory allocation state: %d",
					directory->state);
		}
		assert_zero_dev(directory);

		fbr_fs_stat_add(&fs->stats.flush_conflicts);

		(*attempts)++;
		if (*attempts >= fbr_fs_param_value(fs->config.flush_attempts)) {
			fs->log("FLUSH flush_attempts limit hit on alloc");
			return NULL;
		}
		if (fbr_fs_timeout_expired(time_start, fs->config.flush_timeout_sec)) {
			fs->log("FLUSH flush_timeout_sec limit hit on alloc");
			return NULL;
		}
	}

	assert_dev(directory->state == FBR_DIRSTATE_LOADING);

	return directory;
}

int
fbr_directory_flush(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    enum fbr_flush_flags flags)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	fbr_inode_t inode = file->parent_inode;
	struct fbr_file *parent = fbr_inode_take(fs, inode);
	if (!parent) {
		fs->log("FLUSH parent inode missing (%lu)", inode);
		return ENOENT;
	}

	struct fbr_path_name dirname;
	char buf[PATH_MAX];
	fbr_path_get_full(&parent->path, &dirname, buf, sizeof(buf));
	fbr_inode_release(fs, &parent);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fs->log("FLUSH invoked directory: '%s' file: '%s'", dirname.name, filename.name);

	int add_file = 0;
	int add_file_init = 0;
	if (file->state == FBR_FILE_INIT) {
		add_file = 1;
		add_file_init = 1;
	}

	// Read from dindex
	struct fbr_directory *directory = NULL;
	int wait_for_new = 1;

	do {
		directory = fbr_dindex_take(fs, &dirname, wait_for_new);
		if (directory) {
			fbr_directory_ok(directory);
			assert_dev(directory->state >= FBR_DIRSTATE_OK);
			if (directory->state == FBR_DIRSTATE_ERROR) {
				assert_dev(wait_for_new);
				fbr_dindex_release(fs, &directory);
			}
		}

		if (!wait_for_new) {
			break;
		}
		wait_for_new = 0;
	} while (!directory);

	// dindex empty, read from index store
	if (!directory) {
		directory = fbr_directory_alloc(fs, &dirname, inode);
		fbr_directory_ok(directory);

		switch (directory->state) {
			case FBR_DIRSTATE_ERROR:
				// inode is stale, a top level change was made
				fbr_dindex_release(fs, &directory);
				return ENOENT;
			case FBR_DIRSTATE_OK:
				break;
			case FBR_DIRSTATE_LOADING:
				if (add_file_init) {
					file->state = FBR_FILE_OK;
					file->generation = 0;

					fbr_directory_add_file(fs, directory, file);

					add_file_init = 0;
				}

				fbr_index_read(fs, directory);

				if (directory->state == FBR_DIRSTATE_ERROR) {
					fbr_dindex_release(fs, &directory);
					return EIO;
				}
				break;
			default:
				fbr_ABORT("FLUSH bad directory allocation state: %d",
					directory->state);
		}
	}

	// Start sync/write loop

	unsigned int attempts = 0;
	double time_start = fbr_get_time();
	unsigned long last_generation = 0;
	struct fbr_index_data index_data;
	int ret = EIO;

	while (directory) {
		assert_dev(directory->state == FBR_DIRSTATE_OK);

		fs->log("FLUSH directory: '%s' found generation: %lu attempts: %u", dirname.name,
			directory->generation, attempts);

		if (directory->generation == last_generation) {
			// TODO
			fs->log("FLUSH warning generation hasn't changed");
		}
		last_generation = directory->generation;

		// Lock on LOADING state
		struct fbr_directory *new_directory = _directory_get_loading(fs, &dirname, inode,
			&directory, &attempts, time_start);
		if (!new_directory) {
			fbr_dindex_release(fs, &directory);
			ret = EIO;
			break;
		}
		assert_dev(new_directory->state == FBR_DIRSTATE_LOADING);

		// Prep new_directory
		struct fbr_directory *previous = new_directory->previous;
		if (!previous) {
			previous = directory;
		}

		fbr_directory_copy(fs, new_directory, previous);

		new_directory->generation++;

		fbr_file_LOCK(fs, file);

		if (add_file_init) {
			file->state = FBR_FILE_OK;

			struct fbr_file *existing = fbr_directory_find_file(new_directory,
				filename.name, filename.len);

			if (!existing) {
				file->generation = 1;
				fbr_directory_add_file(fs, new_directory, file);
			} else {
				assert(existing == file);
				file->generation++;

				add_file_init = 0;
			}
		} else {
			assert_dev(file == fbr_directory_find_file(new_directory, filename.name,
				filename.len));
			file->generation++;
		}

		fs->log("FLUSH file: '%s' generation: %lu", filename.name, file->generation);

		fbr_index_data_init(fs, &index_data, new_directory, previous, file, wbuffers,
			flags);

		int retry = 0;

		ret = fbr_index_write(fs, &index_data);
		if (!ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);
		} else {
			fs->log("FLUSH fbr_index_write(new_directory) failed (%d %s)", ret,
				strerror(ret));

			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);

			if (!add_file_init) {
				file->generation--;
			}

			if (ret == EAGAIN) {
				retry = 1;
			}
		}

		add_file_init = 0;

		fbr_file_UNLOCK(file);

		fbr_index_data_free(&index_data);
		fbr_dindex_release(fs, &directory);
		fbr_dindex_release(fs, &new_directory);

		if (!ret || !retry) {
			break;
		}

		fbr_fs_stat_add(&fs->stats.flush_conflicts);

		attempts++;
		if (attempts >= fbr_fs_param_value(fs->config.flush_attempts)) {
			fs->log("FLUSH flush_attempts limit hit on write");
			break;
		}
		if (fbr_fs_timeout_expired(time_start, fs->config.flush_timeout_sec)) {
			fs->log("FLUSH flush_timeout_sec limit hit on write");
			break;
		}

		// Retry, lock on LOADING state
		directory = _directory_get_loading(fs, &dirname, inode, NULL, &attempts,
			time_start);
		if (!directory) {
			ret = EIO;
			break;
		}
		assert_dev(directory->state == FBR_DIRSTATE_LOADING);

		// Read from index store
		if (add_file) {
			file->generation = 0;
			fbr_directory_add_file(fs, directory, file);
		}

		fbr_index_read(fs, directory);
		if (directory->state == FBR_DIRSTATE_ERROR) {
			fbr_dindex_release(fs, &directory);
			ret = EIO;
			break;
		}
	}

	if (ret && add_file) {
		file->state = FBR_FILE_INIT;
	}

	return ret;
}
