/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

static struct fbr_directory *
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
				break;
			case FBR_DIRSTATE_LOADING:
				continue;
			default:
				fbr_ABORT("FLUSH bad directory allocation state: %d",
					directory->state);
		}
		assert_zero_dev(directory);

		fbr_stat_add(&fs->stats.flush_conflicts);

		(*attempts)++;
		if (*attempts >= fbr_fs_param_value(fs->config.flush_attempts)) {
			fbr_rlog(FBR_LOG_ERROR, "flush_attempts limit hit on alloc");
			return NULL;
		} else if (fbr_fs_timeout_expired(time_start, fs->config.flush_timeout_sec)) {
			fbr_rlog(FBR_LOG_ERROR, "flush_timeout_sec limit hit on alloc");
			return NULL;
		}
	}

	assert_dev(directory->state == FBR_DIRSTATE_LOADING);

	return directory;
}

static int
_flush_merge(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_file *file,
    int flags)
{
	assert_dev(fs);
	assert_dev(directory);
	assert_dev(directory->state == FBR_DIRSTATE_LOADING);
	assert_dev(file);
	assert_dev(fbr_is_flag(flags, FBR_FLUSH_WBUFFER | FBR_FLUSH_MKDIR));

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_rlog(FBR_LOG_FLUSH, "Starting merge on %s", filename.name);

	if (file->state == FBR_FILE_INIT) {
		file->state = FBR_FILE_OK;
	}

	struct fbr_file *latest = fbr_directory_find_file(directory, filename.name,
		filename.length);

	int merge = 0;
	if (latest && latest->generation > file->generation) {
		assert(latest != file);
		merge = 1;
	} else if (latest) {
		assert(latest == file);
	}

	if (fbr_is_flag(flags, FBR_FLUSH_WBUFFER)) {
		assert_zero_dev(fbr_is_flag(flags, FBR_FLUSH_MKDIR));
		if (merge) {
			fbr_file_merge(fs, latest, file);
			fbr_directory_remove_file(fs, directory, latest);
			fbr_directory_add_file(fs, directory, file);
		} else if (!latest) {
			fbr_directory_add_file(fs, directory, file);
		}

		file->generation++;
	} else if (fbr_is_flag(flags, FBR_FLUSH_MKDIR)) {
		assert_dev(flags == FBR_FLUSH_MKDIR);
		if (latest) {
			return EEXIST;
		}

		fbr_directory_add_file(fs, directory, file);

		file->generation = 1;
	} else {
		fbr_ABORT("Bad flags");
	}

	return 0;
}

int
fbr_directory_flush(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    enum fbr_flush_flags flags)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(fbr_is_flag(flags, FBR_FLUSH_WBUFFER | FBR_FLUSH_MKDIR));

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

	fbr_rlog(FBR_LOG_FLUSH, "directory: '%s' file: '%s'", dirpath.path.name, filename.name);

	int merged = 0;

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
				fbr_index_read(fs, directory, 1, 0);

				if (directory->state == FBR_DIRSTATE_ERROR) {
					fbr_dindex_release(fs, &directory);
					return EIO;
				}

				ret = _flush_merge(fs, directory, file, flags);

				fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

				if (ret) {
					return ret;
				}

				merged = 1;

				break;
			default:
				fbr_ABORT("FLUSH bad directory allocation state: %d",
					directory->state);
		}
	}

	// Start sync/write loop

	unsigned int attempts = 0;
	unsigned int generation_matches = 0;
	unsigned long last_generation = 0;
	double time_start = fbr_get_time();
	struct fbr_index_data index_data;
	ret = EIO;

	while (directory) {
		assert_dev(directory->state == FBR_DIRSTATE_OK);

		fbr_rlog(FBR_LOG_FLUSH, "directory: '%s' found generation: %lu attempts: %u",
			dirpath.path.name, directory->generation, attempts);

		if (attempts && directory->generation == last_generation) {
			generation_matches++;
			fbr_rlog(FBR_LOG_FLUSH, "warning generation hasn't changed (%u)",
				generation_matches);

			if (generation_matches > 3) {
				fbr_dindex_release(fs, &directory);
				ret = EIO;
				break;
			} else {
				fbr_sleep_backoff(attempts);
			}
		} else {
			last_generation = directory->generation;
			generation_matches = 0;
		}

		// Lock on LOADING state
		struct fbr_directory *new_directory = _directory_get_loading(fs, &dirpath.path,
			inode, &directory, &attempts, time_start);
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

		if (!merged) {
			_flush_merge(fs, new_directory, file, flags);
			merged = 1;
		} else {
			assert_dev(file == fbr_directory_find_file(new_directory, filename.name,
				filename.length));
			assert_dev(file->generation);
		}

		fbr_file_LOCK(fs, file);

		fbr_index_data_init(fs, &index_data, new_directory, previous, file, wbuffers,
			flags);

		int retry = 0;

		ret = fbr_index_write(fs, &index_data);
		if (!ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);
		} else {
			fbr_rlog(FBR_LOG_ERROR, "flush fbr_index_write(new_directory) failed"
				" (%d %s)", ret, strerror(ret));

			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);

			file->generation--;

			if (ret == EAGAIN) {
				retry = 1;
			}
		}

		fbr_file_UNLOCK(file);

		fbr_index_data_free(&index_data);
		fbr_dindex_release(fs, &directory);
		fbr_dindex_release(fs, &new_directory);

		if (!ret || !retry) {
			break;
		}

		fbr_stat_add(&fs->stats.flush_conflicts);

		attempts++;
		if (attempts >= fbr_fs_param_value(fs->config.flush_attempts)) {
			fbr_rlog(FBR_LOG_ERROR, "flush_attempts limit hit on write");
			break;
		} else if (fbr_fs_timeout_expired(time_start, fs->config.flush_timeout_sec)) {
			fbr_rlog(FBR_LOG_ERROR, "flush_timeout_sec limit hit on write");
			break;
		}

		// Retry, lock on LOADING state
		directory = _directory_get_loading(fs, &dirpath.path, inode, NULL, &attempts,
			time_start);
		if (!directory) {
			ret = EIO;
			break;
		}
		assert_dev(directory->state == FBR_DIRSTATE_LOADING);

		fbr_index_read(fs, directory, 1, attempts);

		if (directory->state == FBR_DIRSTATE_ERROR) {
			fbr_dindex_release(fs, &directory);
			ret = EIO;
			break;
		}

		ret = _flush_merge(fs, directory, file, flags);

		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);

		if (ret) {
			break;
		}
	}

	return ret;
}
