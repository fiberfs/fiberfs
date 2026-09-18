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
    struct fbr_wbuffer *wbuffers, const char *filename, enum fbr_flush_flags flags)
{
	assert(flush_data);
	fbr_file_ok(file);
	assert(fbr_is_flag(flags, FBR_FLUSH_WBUFFER | FBR_FLUSH_MKDIR | FBR_FLUSH_ATTR |
		FBR_FLUSH_RESIZE | FBR_FLUSH_NEW_FILE | FBR_FLUSH_UNLINK | FBR_FLUSH_RMDIR |
		FBR_FLUSH_RENAME));

	fbr_zero(flush_data);
	flush_data->file = file;
	flush_data->_file = file;
	flush_data->flags = flags;

	if (attr) {
		assert(fbr_is_flag(flags, FBR_FLUSH_ATTR | FBR_FLUSH_RESIZE));
		flush_data->attr = attr;
	}

	if (wbuffers) {
		fbr_wbuffer_ok(wbuffers);
		assert(fbr_is_flag(flags, FBR_FLUSH_WBUFFER));
		assert_zero(fbr_is_flag(flags, FBR_FLUSH_MEM_ONLY));
		flush_data->wbuffers = wbuffers;
	}

	if (filename) {
		assert(fbr_is_flag(flags, FBR_FLUSH_RENAME));
		fbr_path_name_init(&flush_data->filename, filename);
	}

	fbr_flush_data_ok(flush_data);
}

static void
_flush_data_free(struct fbr_flush_data *flush_data_cmds)
{
	assert(flush_data_cmds);

	while (flush_data_cmds) {
		struct fbr_flush_data *flush_data = flush_data_cmds;
		fbr_flush_data_ok(flush_data);

		flush_data_cmds = flush_data->next;

		fbr_zero(flush_data);
	}
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

static struct fbr_file *
_flush_find_alias(struct fbr_file *file)
{
	while (file) {
		fbr_file_ok(file);

		if (file->alias_file) {
			file = file->alias_file;
			continue;
		}

		break;
	}

	return file;
}

static int
_flush_contains_file(struct fbr_flush_data *flush_data, struct fbr_file *file)
{
	assert_dev(flush_data);
	assert_dev(flush_data->head);
	assert_dev(file);

	struct fbr_flush_data *flush_data_ptr = flush_data->head;

	while (flush_data_ptr != flush_data) {
		fbr_flush_data_ok(flush_data_ptr);

		if (flush_data_ptr->file == file) {
			return 1;
		}

		flush_data_ptr = flush_data_ptr->next;
	}

	return 0;
}

static int
_flush_merge(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_flush_data *flush_data)
{
	assert_dev(fs);
	assert_dev(directory);
	assert_dev(directory->state == FBR_DIRSTATE_LOADING);
	assert_dev(flush_data);
	assert_dev(flush_data->flags);
	assert_zero_dev(flush_data->latest);
	assert_zero_dev(flush_data->prev);

	struct fbr_file *file = flush_data->file;
	assert_dev(file);

	fbr_file_LOCK(fs, file);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_rlog(FBR_LOG_MERGE, "starting merge '%s' curr gen: %lu inode: %lu dir new gen: %lu",
		filename.name, file->generation, file->inode, directory->generation);

	struct fbr_file *latest = fbr_directory_find_file(directory, filename.name,
		filename.length);

	int latest_modified = 0;

	if (latest && latest != file) {
		assert_zero(_flush_contains_file(flush_data, latest));

		if (latest->generation > file->generation) {
			fbr_rlog(FBR_LOG_FLUSH, "new remote generation found (%lu > %lu)",
				latest->generation, file->generation);
		} else {
			fbr_rlog(FBR_LOG_FLUSH, "local update found (%lu != %lu)",
				latest->inode, file->inode);
		}

		fbr_file_LOCK(fs, latest);

		flush_data->latest = latest;
		latest_modified = 1;
	}

	fbr_file_generation(file);

	if (fbr_is_flag(flush_data->flags, FBR_FLUSH_WBUFFER)) {
		assert_dev(flush_data->flags < FBR_FLUSH_MKDIR);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_WBUFFER");

		struct fbr_file *alias = _flush_find_alias(file->alias_file);
		if (alias) {
			fbr_file_ok(alias);
			assert_zero(_flush_contains_file(flush_data, alias));

			fbr_file_LOCK(fs, alias);

			fbr_path_get_file(&alias->path, &filename);
			fbr_rlog(FBR_LOG_FLUSH, "alias detected: '%s'", filename.name);

			flush_data->file = alias;
			flush_data->prev = file;

			file = alias;
			latest = alias;
			latest_modified = 0;
		}

		if (latest && S_ISDIR(latest->mode)) {
			fbr_rlog(FBR_LOG_FLUSH, "wbuffer EISDIR detected");
			return EISDIR;
		} else if (latest_modified) {
			fbr_file_merge(fs, latest, file);
			fbr_directory_remove_file(fs, directory, &latest);
			fbr_directory_add_file(fs, directory, file);

			fbr_file_generation(file);
		} else if (!latest) {
			fbr_directory_add_file(fs, directory, file);
		} else {
			assert_dev(latest == file);
		}
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_MKDIR)) {
		assert_dev(flush_data->flags == FBR_FLUSH_MKDIR);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_MKDIR");

		if (latest) {
			fbr_rlog(FBR_LOG_FLUSH, "mkdir EEXIST detected");
			return EEXIST;
		}

		fbr_directory_add_file(fs, directory, file);
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_ATTR)) {
		assert_dev(flush_data->flags < FBR_FLUSH_NEW_FILE);
		assert_dev(flush_data->attr);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_ATTR");

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

		if (latest_modified) {
			fbr_file_generation(clone);
		}

		fbr_directory_remove_file(fs, directory, &latest);
		fbr_directory_add_file(fs, directory, clone);

		assert_zero_dev(latest);

		fbr_file_LOCK(fs, clone);

		flush_data->file = clone;
		flush_data->prev = file;

		file = clone;
		latest = clone;
		latest_modified = 0;
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_NEW_FILE)) {
		assert_dev(flush_data->flags < FBR_FLUSH_UNLINK);
		assert_zero(file->size);
		assert_zero_dev(file->body.chunks);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_NEW_FILE");

		if (!latest) {
			fbr_directory_add_file(fs, directory, file);
		} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_NEW_EXCLUSIVE)) {
			fbr_rlog(FBR_LOG_FLUSH, "EEXIST detected (want exclusive)");
			return EEXIST;
		}
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_UNLINK)) {
		assert_dev(flush_data->flags == FBR_FLUSH_UNLINK);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_UNLINK");

		if (!latest) {
			fbr_rlog(FBR_LOG_FLUSH, "unlink ENOENT detected");
			return ENOENT;
		} else if (S_ISDIR(latest->mode)) {
			fbr_rlog(FBR_LOG_FLUSH, "unlink EISDIR detected");
			return EISDIR;
		}

		fbr_directory_remove_file(fs, directory, &latest);
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_RMDIR)) {
		assert_dev(flush_data->flags == FBR_FLUSH_RMDIR);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_RMDIR");

		if (!latest) {
			fbr_rlog(FBR_LOG_FLUSH, "unlink ENOENT detected");
			return ENOENT;
		} else if (!S_ISDIR(latest->mode)) {
			fbr_rlog(FBR_LOG_FLUSH, "unlink EISDIR detected");
			return ENOTDIR;
		}

		fbr_directory_remove_file(fs, directory, &latest);
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_RENAME)) {
		assert_dev(flush_data->flags == FBR_FLUSH_RENAME);
		assert_dev(flush_data->filename.length);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_RENAME");

		if (!latest) {
			fbr_rlog(FBR_LOG_FLUSH, "rename ENOENT detected (source)");
			return ENOENT;
		} else if (S_ISDIR(latest->mode)) {
			fbr_rlog(FBR_LOG_FLUSH, "rename EISDIR detected");
			return EISDIR;
		} else if (latest_modified) {
			fbr_file_generation(latest);
		} else {
			assert_dev(file == latest);
		}

		struct fbr_file *dest = fbr_directory_find_file(directory,
			flush_data->filename.name, flush_data->filename.length);

		if (dest) {
			if (S_ISDIR(dest->mode)) {
				fbr_rlog(FBR_LOG_FLUSH, "rename EISDIR detected (dest)");
				return EISDIR;
			}

			fbr_directory_remove_file(fs, directory, &dest);
		}

		dest = fbr_file_alloc(fs, directory, &flush_data->filename);
		fbr_file_ok(dest);
		assert_dev(dest->state == FBR_FILE_INIT);

		if (latest->alias) {
			dest->alias = fbr_path_shared_take(latest->alias);
		} else {
			dest->alias = fbr_path_shared_alloc(&filename);
		}

		fbr_inode_add(fs, dest);

		assert_zero_dev(latest->alias_file);
		latest->alias_file = dest;
		latest->state = FBR_FILE_DELETED;

		fbr_file_merge(fs, latest, dest);
		fbr_directory_remove_file(fs, directory, &latest);

		dest->state = FBR_FILE_OK;

		if (latest_modified) {
			fbr_inode_add(fs, dest);

			assert_zero_dev(file->alias_file);
			file->alias_file = dest;
			file->state = FBR_FILE_DELETED;

			flush_data->file = latest;
			flush_data->latest = file;

			file = latest;
			latest_modified = 0;
		}
	}

	if (fbr_is_flag(flush_data->flags, FBR_FLUSH_RESIZE)) {
		assert_dev(flush_data->attr);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_RESIZE");

		if (!latest) {
			fbr_rlog(FBR_LOG_FLUSH, "resize ENOENT detected");
			return ENOENT;
		} else if (S_ISDIR(latest->mode)) {
			fbr_rlog(FBR_LOG_FLUSH, "resize EISDIR detected");
			return EISDIR;
		} else if (latest_modified) {
			fbr_file_generation(latest);
		} else {
			assert_dev(file == latest);
		}

		latest->size = flush_data->attr->st_size;
	}

	if (file->state == FBR_FILE_INIT) {
		file->state = FBR_FILE_OK;
	}

	return 0;
}

static void
_flush_done(struct fbr_fs *fs, struct fbr_flush_data *flush_data, int error)
{
	assert_dev(fs);
	fbr_flush_data_ok(flush_data);
	assert_dev(flush_data->flags);

	struct fbr_file *file = flush_data->file;
	assert_dev(file);

	if (fbr_is_flag(flush_data->flags, FBR_FLUSH_RENAME) && error) {
		assert_dev(flush_data->file->alias_file);
		fbr_inode_release(fs, &flush_data->file->alias_file);

		if (flush_data->latest && flush_data->latest->alias_file) {
			fbr_file_ok(flush_data->latest);
			fbr_inode_release(fs, &flush_data->latest->alias_file);
		}
	}

	fbr_file_UNLOCK(file);

	if (flush_data->latest) {
		fbr_file_UNLOCK(flush_data->latest);
		flush_data->latest = NULL;
	}

	if (flush_data->prev) {
		fbr_file_UNLOCK(flush_data->prev);
		flush_data->prev = NULL;
	}

	flush_data->file = flush_data->_file;
}

static int
_flush_cmds_merge(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_flush_data *flush_data_cmds)
{
	assert_dev(fs);
	assert_dev(directory);
	assert_dev(flush_data_cmds);

	struct fbr_flush_data *flush_data = flush_data_cmds;
	size_t cmd_count = 0;

	while (flush_data) {
		fbr_flush_data_ok(flush_data);
		assert_dev(flush_data->flags);

		flush_data->head = flush_data_cmds;

		struct fbr_file *file = flush_data->file;
		assert(file->parent_inode == flush_data_cmds->file->parent_inode);

		fbr_rlog(FBR_LOG_FLUSH, "flush command: %zu", cmd_count);

		assert_zero(_flush_contains_file(flush_data, file));

		int ret = _flush_merge(fs, directory, flush_data);
		if (ret) {
			struct fbr_flush_data *flush_data_ptr = flush_data_cmds;
			while (flush_data_ptr != flush_data) {
				_flush_done(fs, flush_data_ptr, ret);
				flush_data_ptr = flush_data_ptr->next;
			}

			_flush_done(fs, flush_data, ret);

			return ret;
		}

		flush_data = flush_data->next;
		cmd_count++;
	}

	return 0;
}

int
fbr_flush(struct fbr_fs *fs, struct fbr_flush_data *flush_data_cmds)
{
	fbr_fs_ok(fs);
	fbr_flush_data_ok(flush_data_cmds);

	fbr_inode_t inode = flush_data_cmds->file->parent_inode;
	struct fbr_file *parent = fbr_inode_take(fs, inode);
	if (!parent) {
		fbr_rlog(FBR_LOG_ERROR, "flush parent inode missing (%lu)", inode);
		return ENOENT;
	}

	struct fbr_fullpath_name dirpath;
	fbr_path_get_full(&parent->path, &dirpath);
	fbr_inode_release(fs, &parent);

	struct fbr_fs_timeout timeout;
	fbr_fs_timeout_init(&timeout);

	fbr_rlog(FBR_LOG_FLUSH, "directory: '%s'", dirpath.path.name);

	struct fbr_directory *directory = fbr_directory_get(fs, &dirpath.path, inode, 1, 0);
	if (!directory) {
		return ENOENT;
	}

	// Start sync/write loop

	struct fbr_index_data _index_data_cmds[FBR_INDEX_MAX_CMDS];
	struct fbr_index_data *index_data_cmds;

	unsigned int version_matches = 0;
	fbr_id_t last_version = 0, directory_version;
	int ret = EIO;
	char errbuf[FBR_STRERROR_LEN];

	while (directory) {
		assert_dev(directory->state == FBR_DIRSTATE_OK);

		index_data_cmds = NULL;

		fbr_rlog(FBR_LOG_FLUSH, "directory: '%s' found generation: %lu attempts: %u",
			dirpath.path.name, directory->generation, timeout.attempts);

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

		ret = _flush_cmds_merge(fs, new_directory, flush_data_cmds);
		if (ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);
			fbr_dindex_release(fs, &new_directory);
			fbr_dindex_release(fs, &directory);

			break;
		}

		size_t count = 0;
		struct fbr_index_data *index_last = NULL;

		struct fbr_flush_data *flush_data = flush_data_cmds;
		while (flush_data) {
			fbr_flush_data_ok(flush_data);

			assert(count < fbr_array_len(_index_data_cmds));
			struct fbr_index_data *index_data = &_index_data_cmds[count];

			fbr_index_data_init(fs, index_data, new_directory, previous,
				flush_data->file, flush_data->wbuffers, flush_data->flags);

			if (!index_last) {
				assert_zero_dev(index_data_cmds);
				index_data_cmds = index_data;
			} else {
				assert_zero_dev(fbr_is_flag(index_data->flags,
					FBR_FLUSH_MEM_ONLY));
				assert_zero_dev(index_data->next);

				index_last->next = index_data;
			}

			index_last = index_data;
			flush_data = flush_data->next;
			count++;
		}

		assert_dev(index_data_cmds);

		int retry = 0;

		ret = fbr_index_write(fs, index_data_cmds);

		flush_data = flush_data_cmds;
		while (flush_data) {
			_flush_done(fs, flush_data, ret);
			flush_data = flush_data->next;
		}

		fbr_rlog(FBR_LOG_FLUSH, "completed: %d (inode: %lu gen: %lu)", ret,
			new_directory->inode, new_directory->generation);

		if (!ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);
		} else {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);

			if (ret == EAGAIN) {
				retry = 1;
			}

			fbr_rlog(FBR_LOG_ERROR, "flush fbr_index_write failed (%d %s) retry: %d",
				ret, fbr_berror(ret, errbuf), retry);
		}

		directory_version = directory->version;

		fbr_index_data_free(index_data_cmds);
		fbr_dindex_release(fs, &new_directory);
		fbr_dindex_release(fs, &directory);

		if (!ret || !retry) {
			break;
		}

		fbr_stat_add(&fs->stats.flush_conflicts);

		if (fbr_fs_is_timeout(fs, &timeout)) {
			break;
		} else if (directory_version == last_version) {
			version_matches++;

			fbr_rlog(FBR_LOG_FLUSH, "warning version hasn't changed (%u)",
				version_matches);

			if (version_matches >= FBR_MAX_VERSION_ERRORS) {
				ret = EIO;
				break;
			} else {
				fbr_sleep_backoff(timeout.attempts);
			}
		} else {
			last_version = directory_version;
			version_matches = 0;
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
		fbr_rlog(FBR_LOG_ERROR, "flush failed %d (%s)", ret, fbr_berror(ret, errbuf));
	} else if (fbr_is_flag(flush_data_cmds->flags, FBR_FLUSH_MEM_ONLY)) {
		assert_zero_dev(flush_data_cmds->next);
		fbr_stat_add(&fs->stats.flush_memory);
	} else {
		fbr_stat_add(&fs->stats.flushes);
	}

	return ret;
}

int
fbr_fs_flush(struct fbr_fs *fs, struct fbr_flush_data *flush_data_cmds)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_flush_data_ok(flush_data_cmds);

	int ret = EIO;

	if (fs->store->optional.directory_flush_f) {
		assert_dev(fs->store->optional.directory_flush_f != fbr_fs_flush);
		assert_dev(fs->store->optional.directory_flush_f != fbr_flush);

		ret = fs->store->optional.directory_flush_f(fs, flush_data_cmds);
	} else {
		ret = fbr_flush(fs, flush_data_cmds);
	}

	_flush_data_free(flush_data_cmds);

	return ret;
}
