/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/store/fbr_store.h"

struct fbr_flush_data *
fbr_flush_data_init(struct fbr_flush_data *flush_data, struct fbr_file *file, struct stat *attr,
    struct fbr_wbuffer *wbuffers, const char *filename, enum fbr_flush_flags flags,
    struct fbr_flush_data *current)
{
	fbr_file_ok(file);
	assert(fbr_is_flag(flags, FBR_FLUSH_WBUFFER | FBR_FLUSH_MKDIR | FBR_FLUSH_ATTR |
		FBR_FLUSH_RESIZE | FBR_FLUSH_NEW_FILE | FBR_FLUSH_UNLINK | FBR_FLUSH_RMDIR |
		FBR_FLUSH_RENAME | FBR_FLUSH_DELETE));

	int do_free = 0;

	if (!flush_data) {
		flush_data = malloc(sizeof(*flush_data));
		assert(flush_data);

		do_free = 1;
	}

	fbr_zero(flush_data);
	flush_data->file = file;
	flush_data->_file = file;
	flush_data->flags = flags;
	flush_data->do_free = do_free;

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

	while (current) {
		fbr_flush_data_ok(current);
		assert_dev(current != flush_data);

		if (!current->next) {
			current->next = flush_data;
			break;
		}

		current = current->next;
	}

	fbr_flush_data_ok(flush_data);

	return flush_data;
}

static void
_flush_data_free(struct fbr_flush_data *flush_data_cmds)
{
	assert(flush_data_cmds);

	while (flush_data_cmds) {
		struct fbr_flush_data *flush_data = flush_data_cmds;
		fbr_flush_data_ok(flush_data);

		flush_data_cmds = flush_data->next;

		int do_free = flush_data->do_free;

		fbr_zero(flush_data);

		if (do_free) {
			free(flush_data);
		}
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

// Note: can only be used during flush with a DIRSTATE_LOADING lock
// Note: need source->lock if source state is OK
static void
_flush_set_alias(struct fbr_fs *fs, struct fbr_file *source, struct fbr_file *alias)
{
	assert_dev(fs);
	fbr_file_ok(source);
	fbr_file_ok(alias);
	assert_zero(alias->alias.file);

	fbr_rlog(FBR_LOG_FLUSH, "ALIAS source inode: %lu gen: %lu to inode: %lu gen: %lu",
		source->inode, source->generation, alias->inode, alias->generation);

	fbr_inode_add(fs, alias);

	assert_zero(source->has_alias_file);
	assert_zero(source->alias.file);
	/*
	 * TODO revisit this after rename and make an alias service with locking
	if(source->has_alias_file) {
		assert_dev(source->alias_file);
		fbr_inode_release(fs, &source->alias_file);
	}
	*/

	assert_zero_dev(source->alias.file);

	source->alias.file = alias;
	source->has_alias_file = 1;
}

static void
_flush_queue_alias(struct fbr_flush_data *flush_data, struct fbr_file *source,
    struct fbr_file *alias)
{
	assert_dev(flush_data);
	assert_dev(source);
	assert_zero(source->alias.file);
	assert_dev(alias);
	assert(source != alias);

	for (size_t i = 0; i < fbr_array_len(flush_data->aliases); i++) {
		if (!flush_data->aliases[i].source) {
			flush_data->aliases[i].source = source;
			flush_data->aliases[i].alias = alias;
			return;
		}

		assert(flush_data->aliases[i].source != source);
	}

	fbr_ABORT("Too many aliases");
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
	assert_zero_dev(flush_data->prev_file);

	struct fbr_file *file = flush_data->file;
	assert_dev(file);

	if (!flush_data->skip_lock) {
		fbr_file_LOCK(fs, file);
	}

	int file_new = 0;
	if (file->state == FBR_FILE_INIT || file->local_only) {
		file_new = 1;
	}

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_rlog(FBR_LOG_FLUSH, "FILE '%s' inode: %lu gen: %lu state: %d (directory->gen: %lu)",
		filename.name, file->inode, file->generation, file->state, directory->generation);

	struct fbr_file *latest = NULL;
	int latest_modified = 0;

	if (!flush_data->skip_latest) {
		latest = fbr_directory_find_file(directory, filename.name, filename.length);
	}
	if (latest && latest != file) {
		assert_zero(_flush_contains_file(flush_data, latest));

		if (latest->generation > file->generation) {
			fbr_rlog(FBR_LOG_FLUSH, "LATEST found inode: %lu gen: %lu (new gen)",
				latest->inode, latest->generation);
		} else {
			fbr_rlog(FBR_LOG_FLUSH, "LATEST found inode: %lu gen: %lu (new inode)",
				latest->inode, latest->generation);
		}

		fbr_file_LOCK(fs, latest);

		fbr_inode_add(fs, latest);

		flush_data->latest = latest;
		latest_modified = 1;
	}

	fbr_file_generation(file);

	if (fbr_is_flag(flush_data->flags, FBR_FLUSH_WBUFFER)) {
		assert_dev(flush_data->flags < FBR_FLUSH_MKDIR);
		assert_zero_dev(flush_data->skip_latest);

		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_WBUFFER");

		if (latest_modified && fbr_alias_path_cmp(file, latest)) {
			fbr_ABORT("TODO alias mismatch");
			// TODO delete file, use latest
		}

		struct fbr_file *alias = fbr_file_get_alias(fs, file->alias.file);
		if (alias && alias != file->alias.file) {
			// TODO implement this deferred to reduce alias chaining
			//_flush_set_alias(fs, file, alias);
		}
		if (!alias && latest) {
			alias = fbr_file_get_alias(fs, latest->alias.file);
			if (alias && alias != latest->alias.file) {
				assert(alias != file);
				// TODO implement this deferred to reduce alias chaining
				//_flush_set_alias(fs, latest, alias);
			}
		}
		if (alias && alias != latest) {
			fbr_file_ok(alias);
			assert(alias != file);
			assert_zero(_flush_contains_file(flush_data, alias));

			fbr_file_LOCK(fs, alias);

			assert_zero_dev(flush_data->alias_file);
			flush_data->alias_file = alias;

			fbr_path_get_file(&alias->path, &filename);

			// Write isolated to clone when aliasing

			struct fbr_file *clone = fbr_file_clone(fs, directory, alias);
			fbr_file_ok(clone);
			assert_dev(clone->state == FBR_FILE_INIT);

			fbr_file_generation(clone);

			_flush_queue_alias(flush_data, alias, clone);

			int removed = fbr_directory_remove_file(fs, directory, &alias);
			if (!removed) {
				struct fbr_file *dup = fbr_directory_find_file(directory,
					filename.name, filename.length);
				if (dup) {
					fbr_directory_remove_file(fs, directory, &dup);
				}
			}

			fbr_directory_add_file(fs, directory, clone);

			fbr_file_LOCK(fs, clone);

			assert_zero(flush_data->prev_file);
			assert_zero(flush_data->skip_lock);

			flush_data->file = clone;
			flush_data->prev_file = file;

			file = clone;

			latest = clone;
			latest_modified = 0;
		} else if (alias && alias == latest) {
			assert_dev(latest_modified);
			assert_zero(flush_data->prev_file);
			assert_zero(flush_data->skip_lock);

			flush_data->file = latest;
			flush_data->prev_file = file;

			fbr_inode_release(fs, &flush_data->latest);
			assert_zero_dev(flush_data->latest);

			file = latest;
			latest_modified = 0;
		}

		if (latest && S_ISDIR(latest->mode)) {
			fbr_rlog(FBR_LOG_FLUSH, "wbuffer EISDIR detected");
			return EISDIR;
		} else if (latest_modified) {
			fbr_rlog(FBR_LOG_FLUSH, "MERGING file and latest into clone");

			struct fbr_file *clone = fbr_file_clone(fs, directory, file);
			fbr_file_ok(clone);
			assert_dev(clone->state == FBR_FILE_INIT);

			fbr_file_merge(fs, latest, clone);
			fbr_file_generation(clone);

			_flush_queue_alias(flush_data, file, clone);
			_flush_queue_alias(flush_data, latest, clone);

			fbr_directory_remove_file(fs, directory, &latest);
			fbr_directory_add_file(fs, directory, clone);

			fbr_file_LOCK(fs, clone);

			assert_zero(flush_data->prev_file);
			assert_zero(flush_data->skip_lock);

			flush_data->file = clone;
			flush_data->prev_file = file;

			file = clone;

			latest = clone;
			latest_modified = 0;
		} else if (!latest && file_new) {
			fbr_rlog(FBR_LOG_FLUSH, "ADDING file");
			fbr_directory_add_file(fs, directory, file);
		} else if (!latest) {
			struct fbr_file *file_new = fbr_file_alloc(fs, directory, &filename);
			fbr_file_ok(file_new);
			assert_dev(file_new->state == FBR_FILE_INIT);

			fbr_rlog(FBR_LOG_FLUSH, "NEW file inode: %lu gen: %lu", file_new->inode,
				file_new->generation);

			fbr_file_generation(file_new);
			_flush_queue_alias(flush_data, file, file_new);

			fbr_file_LOCK(fs, file_new);

			assert_zero(flush_data->prev_file);
			assert_zero(flush_data->skip_lock);

			flush_data->file = file_new;
			flush_data->prev_file = file;

			file = file_new;
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

		assert_zero(flush_data->prev_file);
		assert_zero(flush_data->skip_lock);

		flush_data->file = clone;
		flush_data->prev_file = file;

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
		} else if (latest_modified) {
			_flush_queue_alias(flush_data, file, latest);
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
		assert_dev(flush_data->flags == FBR_FLUSH_RENAME ||
			flush_data->flags == (FBR_FLUSH_RENAME | FBR_FLUSH_RENAME_UNIQUE));
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

		// TODO flush_data->alias_latest
		assert_zero(latest->has_alias_file);

		struct fbr_file *dest = fbr_directory_find_file(directory,
			flush_data->filename.name, flush_data->filename.length);

		if (dest) {
			if (S_ISDIR(dest->mode)) {
				fbr_rlog(FBR_LOG_FLUSH, "rename EISDIR detected (dest)");
				return EISDIR;
			} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_RENAME_UNIQUE)) {
				fbr_rlog(FBR_LOG_FLUSH, "rename EEXIST detected (dest)");
				return EEXIST;
			}

			fbr_rlog(FBR_LOG_FLUSH, "DELETE dest '%s' inode: %lu gen: %lu",
				flush_data->filename.name, dest->inode, dest->generation);

			struct fbr_flush_data *flush_rm = fbr_flush_data_init(NULL, dest, NULL,
				NULL, NULL, FBR_FLUSH_DELETE, flush_data);

			flush_rm->skip_latest = 1;

			fbr_directory_remove_file(fs, directory, &dest);
		}

		dest = fbr_file_alloc(fs, directory, &flush_data->filename);
		fbr_file_ok(dest);
		assert_dev(dest->state == FBR_FILE_INIT);

		fbr_rlog(FBR_LOG_FLUSH, "NEW dest '%s' inode: %lu gen: %lu",
			flush_data->filename.name, dest->inode, dest->generation);

		if (fbr_has_alias_path(latest)) {
			fbr_alias_path_take(fs, latest, dest);
			assert_dev(fbr_has_alias_path(dest));
		}

		fbr_file_merge(fs, latest, dest);
		fbr_file_generation(dest);
		_flush_queue_alias(flush_data, latest, dest);

		if (!fbr_has_alias_path(dest)) {
			fbr_alias_path_alloc(fs, dest, &filename);
			assert_dev(fbr_has_alias_path(dest));
		}

		if (latest_modified) {
			struct fbr_file *alias_file = fbr_file_find_alias(fs, file);
			if (alias_file != latest) {
				if (alias_file != file) {
					assert_zero_dev(flush_data->alias_file);
					flush_data->alias_file = alias_file;

					fbr_file_LOCK(fs, alias_file);
				}

				_flush_queue_alias(flush_data, alias_file, dest);
			}
		}

		fbr_directory_remove_file(fs, directory, &latest);

		fbr_file_LOCK(fs, dest);

		assert_zero(flush_data->prev_file);
		assert_zero(flush_data->skip_lock);

		flush_data->file = dest;
		flush_data->prev_file = file;

		file = dest;
	} else if (fbr_is_flag(flush_data->flags, FBR_FLUSH_DELETE)) {
		fbr_rlog(FBR_LOG_FLUSH, "FBR_FLUSH_DELETE");
		assert_zero_dev(latest);
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

	if (!error && file->state == FBR_FILE_INIT) {
		file->state = FBR_FILE_OK;
	}

	// TODO move this after unlocking everything, non-alias writes will be merged
	for (size_t i = 0; i < fbr_array_len(flush_data->aliases); i++) {
		if (!error && flush_data->aliases[i].source) {
			struct fbr_file *source = flush_data->aliases[i].source;
			assert_zero(source->has_alias_file);
			assert_zero(source->alias.file);

			_flush_set_alias(fs, source, flush_data->aliases[i].alias);
		}

		fbr_zero(&flush_data->aliases[i]);
	}

	if (!flush_data->skip_lock) {
		fbr_file_UNLOCK(file);
	}
	if (flush_data->latest) {
		fbr_file_UNLOCK(flush_data->latest);
		fbr_inode_release(fs, &flush_data->latest);
		assert_zero_dev(flush_data->latest);
	}
	if (flush_data->alias_file) {
		fbr_file_UNLOCK(flush_data->alias_file);
		flush_data->alias_file = NULL;
	}
	if (flush_data->alias_latest) {
		fbr_file_UNLOCK(flush_data->alias_latest);
		flush_data->alias_latest = NULL;
	}
	if (flush_data->prev_file) {
		fbr_file_UNLOCK(flush_data->prev_file);
		flush_data->prev_file = NULL;
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

		fbr_rlog(FBR_LOG_FLUSH, "command: %zu", cmd_count);

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
		fbr_rlog(FBR_LOG_FLUSH, "ERROR parent inode missing (%lu)", inode);
		return ENOENT;
	}

	struct fbr_fullpath_name dirpath;
	fbr_path_get_full(&parent->path, &dirpath);
	fbr_inode_release(fs, &parent);

	struct fbr_fs_timeout timeout;
	fbr_fs_timeout_init(&timeout);

	fbr_rlog(FBR_LOG_FLUSH, "INIT directory: '%s'", dirpath.path.name);

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

		fbr_rlog(FBR_LOG_FLUSH, "LOOP %u directory: '%s' inode: %lu gen: %lu",
			timeout.attempts, dirpath.path.name, previous->inode, previous->generation);

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

			index_data->locked_files[0] = flush_data->latest;
			index_data->locked_files[1] = flush_data->alias_file;
			index_data->locked_files[2] = flush_data->alias_latest;
			index_data->locked_files[3] = flush_data->prev_file;

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

		fbr_rlog(FBR_LOG_FLUSH, "DONE: %d (directory inode: %lu gen: %lu)", ret,
			new_directory->inode, new_directory->generation);

		if (!ret) {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);
		} else {
			fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);

			if (ret == EAGAIN) {
				retry = 1;
			}

			fbr_rlog(FBR_LOG_FLUSH, "ERROR fbr_index_write failed (%d %s) retry: %d",
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

			fbr_rlog(FBR_LOG_FLUSH, "WARNING version hasn't changed (%u)",
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
		fbr_rlog(FBR_LOG_FLUSH, "FAILED %d (%s)", ret, fbr_berror(ret, errbuf));
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
