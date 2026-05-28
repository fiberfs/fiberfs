/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

void
fbr_flush_data_init(struct fbr_flush_data *flush_data, struct fbr_file *file, struct stat *attr,
    struct fbr_wbuffer *wbuffers, enum fbr_flush_flags flags)
{
	assert(flush_data);
	fbr_file_ok(file);
	assert(fbr_is_flag(flags, FBR_FLUSH_WBUFFER | FBR_FLUSH_MKDIR | FBR_FLUSH_ATTR));

	fbr_zero(flush_data);
	flush_data->file = file;
	flush_data->flags = flags;

	if (attr) {
		assert(fbr_is_flag(flags, FBR_FLUSH_ATTR));
		flush_data->attr = attr;
	}

	if (wbuffers) {
		fbr_wbuffer_ok(wbuffers);
		assert(fbr_is_flag(flags, FBR_FLUSH_WBUFFER));
		flush_data->wbuffers = wbuffers;
	}

	fbr_flush_data_ok(flush_data);
}

static void
_flush_data_free(struct fbr_flush_data *flush_data)
{
	fbr_flush_data_ok(flush_data);

	fbr_zero(flush_data);
}

static struct fbr_directory *
_directory_get_loading(struct fbr_fs *fs, struct fbr_path_name *dirname, fbr_inode_t inode,
    struct fbr_directory **previous, struct fbr_fs_timeout *timeout)
{
	assert_dev(fs);
	assert_dev(dirname);
	assert_dev(inode);
	assert_dev(timeout);

	struct fbr_directory *directory = NULL;

	while (!directory) {
		directory = fbr_directory_alloc(fs, dirname, inode);
		fbr_directory_ok(directory);

		switch (directory->state) {
			case FBR_DIRSTATE_ERROR:
				fbr_rlog(FBR_LOG_ERROR, "dindex inode stale (%lu)", inode);
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
				break;
			case FBR_DIRSTATE_LOADING:
				continue;
			default:
				fbr_ABORT("FLUSH bad directory allocation state: %d",
					directory->state);
		}
		assert_zero_dev(directory);

		fbr_stat_add(&fs->stats.flush_conflicts);

		if (fbr_fs_is_timeout(fs, timeout)) {
			return NULL;
		}
	}

	assert_dev(directory->state == FBR_DIRSTATE_LOADING);

	return directory;
}

static int
_flush_merge(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_flush_data *flush_data)
{
	assert_dev(fs);
	assert_dev(directory);
	assert_dev(directory->state == FBR_DIRSTATE_LOADING);
	assert_dev(flush_data);
	assert_dev(flush_data->file);
	assert_dev(flush_data->flags);

	struct fbr_file *file = flush_data->file;

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_rlog(FBR_LOG_FLUSH, "Starting merge on %s", filename.name);

	if (file->state == FBR_FILE_INIT) {
		file->state = FBR_FILE_OK;
	}

	struct fbr_file *latest = fbr_directory_find_file(directory, filename.name,
		filename.length);

	int remote_merge = 0;
	int local_update = 0;
	int ret;

	if (latest && latest->generation > file->generation) {
		assert(latest != file);
		remote_merge = 1;
	} else if (latest && latest != file) {
		local_update = 1;
	}

	file->generation++;

	if (fbr_is_flag(flush_data->flags, FBR_FLUSH_WBUFFER)) {
		assert_zero_dev(fbr_is_flag(flush_data->flags, FBR_FLUSH_MKDIR));
		assert(!file->size || fbr_file_has_wbuffer(file));

		if (remote_merge) {
			fbr_file_merge(fs, latest, file);
			ret = fbr_directory_remove_file(fs, directory, latest);
			assert(ret);
			fbr_directory_add_file(fs, directory, file);

			file->generation++;
		} if (local_update) {
			ret = fbr_directory_remove_file(fs, directory, latest);
			assert(ret);
			fbr_directory_add_file(fs, directory, file);
		} else if (!latest) {
			fbr_directory_add_file(fs, directory, file);
		}
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_MKDIR)) {
		assert_dev(flush_data->flags == FBR_FLUSH_MKDIR);
		if (latest) {
			fbr_rlog(FBR_LOG_FLUSH, "mkdir EEXIST detected");
			return EEXIST;
		}

		assert_dev(file->generation == 1);

		fbr_directory_add_file(fs, directory, file);
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_ATTR)) {
		assert_dev(flush_data->attr);
		if (!latest) {
			fbr_rlog(FBR_LOG_FLUSH, "attr ENOENT detected");
			return ENOENT;
		}

		struct fbr_file *clone = fbr_file_clone(fs, directory, latest);
		fbr_file_ok(clone);
		assert_dev(clone->state == FBR_FILE_INIT);
		assert_dev(clone->inode > latest->inode);
		assert_dev(clone->inode > file->inode);

		fbr_file_set_attr(fs, clone, flush_data->attr);

		clone->generation++;
		clone->state = FBR_FILE_OK;

		ret = fbr_directory_remove_file(fs, directory, latest);
		assert(ret);
		fbr_directory_add_file(fs, directory, clone);
	} else {
		fbr_ABORT("Bad flags");
	}

	return 0;
}

int
fbr_flush(struct fbr_fs *fs, struct fbr_flush_data *flush_data)
{
	fbr_fs_ok(fs);
	fbr_flush_data_ok(flush_data);
	assert_dev(flush_data->flags);

	struct fbr_file *file = flush_data->file;
	fbr_inode_t inode = file->parent_inode;
	struct fbr_file *parent = fbr_inode_take(fs, inode);
	if (!parent) {
		fbr_rlog(FBR_LOG_ERROR, "flush parent inode missing (%lu)", inode);
		return ENOENT;
	}

	struct fbr_fullpath_name dirpath;
	fbr_path_get_full(&parent->path, &dirpath);
	fbr_inode_release(fs, &parent);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	struct fbr_fs_timeout timeout;
	fbr_fs_timeout_init(&timeout);

	fbr_rlog(FBR_LOG_FLUSH, "directory: '%s' file: '%s'", dirpath.path.name, filename.name);

	// Read from dindex
	struct fbr_directory *directory = NULL;
	int wait_for_new = 1;

	do {
		directory = fbr_dindex_take(fs, &dirpath.path, wait_for_new);
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

	int ret;

	// dindex empty, read from index store
	if (!directory) {
		directory = fbr_directory_alloc(fs, &dirpath.path, inode);
		fbr_directory_ok(directory);

		switch (directory->state) {
			case FBR_DIRSTATE_ERROR:
				// inode is stale, a top level change was made
				fbr_dindex_release(fs, &directory);
				return ENOENT;
			case FBR_DIRSTATE_OK:
				break;
			case FBR_DIRSTATE_LOADING:
				fbr_index_read(fs, directory, &timeout, 0);

				if (directory->state == FBR_DIRSTATE_ERROR) {
					fbr_dindex_release(fs, &directory);
					return EIO;
				}

				assert_dev(directory->state == FBR_DIRSTATE_OK);

				break;
			default:
				fbr_ABORT("FLUSH bad directory allocation state: %d",
					directory->state);
		}
	}

	// Start sync/write loop

	struct fbr_index_data index_data;
	unsigned int generation_matches = 0;
	unsigned long last_generation = 0;

	ret = EIO;

	while (directory) {
		assert_dev(directory->state == FBR_DIRSTATE_OK);

		fbr_rlog(FBR_LOG_FLUSH, "directory: '%s' found generation: %lu attempts: %u",
			dirpath.path.name, directory->generation, timeout.attempts);

		if (timeout.attempts && directory->generation == last_generation) {
			generation_matches++;
			fbr_rlog(FBR_LOG_FLUSH, "warning generation hasn't changed (%u)",
				generation_matches);

			if (generation_matches > 3) {
				fbr_dindex_release(fs, &directory);
				ret = EIO;
				break;
			} else {
				fbr_sleep_backoff(timeout.attempts);
			}
		} else {
			last_generation = directory->generation;
			generation_matches = 0;
		}

		// Lock on LOADING state
		struct fbr_directory *new_directory = _directory_get_loading(fs, &dirpath.path,
			inode, &directory, &timeout);
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

		fbr_rlog(FBR_LOG_FLUSH, "file: '%s' generation: %lu", filename.name,
			file->generation);

		ret = _flush_merge(fs, new_directory, flush_data);
		if (ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);
			fbr_dindex_release(fs, &new_directory);
			fbr_dindex_release(fs, &directory);
			break;
		}

		fbr_file_LOCK(fs, file);

		fbr_index_data_init(fs, &index_data, new_directory, previous, file,
			flush_data->wbuffers, flush_data->flags);

		int retry = 0;

		ret = fbr_index_write(fs, &index_data);
		if (!ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);
		} else {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);

			file->generation--;

			if (ret == EAGAIN) {
				retry = 1;
			}

			fbr_rlog(FBR_LOG_ERROR, "flush fbr_index_write(new_directory) failed"
				" (%d %s) retry: %d", ret, strerror(ret), retry);
		}

		fbr_file_UNLOCK(file);

		fbr_index_data_free(&index_data);
		fbr_dindex_release(fs, &new_directory);
		fbr_dindex_release(fs, &directory);

		if (!ret || !retry) {
			break;
		}

		fbr_stat_add(&fs->stats.flush_conflicts);

		if (fbr_fs_is_timeout(fs, &timeout)) {
			break;
		}

		// Retry, load from S3
		directory = fbr_directory_load(fs, &dirpath.path, inode, 1);
		if (!directory) {
			ret = EIO;
			break;
		}

		assert_dev(directory->state == FBR_DIRSTATE_OK);
	}

	if (ret) {
		fbr_rlog(FBR_LOG_ERROR, "flush failed %s (%d)", strerror(ret), ret);
	}

	return ret;
}

int
fbr_fs_flush(struct fbr_fs *fs, struct fbr_flush_data *flush_data)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_flush_data_ok(flush_data);

	int ret = EIO;

	if (fs->store->optional.directory_flush_f) {
		assert_dev(fs->store->optional.directory_flush_f != fbr_fs_flush);
		assert_dev(fs->store->optional.directory_flush_f != fbr_flush);

		ret = fs->store->optional.directory_flush_f(fs, flush_data);
	} else {
		ret = fbr_flush(fs, flush_data);
	}

	_flush_data_free(flush_data);

	return ret;
}
