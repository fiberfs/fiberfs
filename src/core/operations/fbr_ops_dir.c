/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/store/fbr_store.h"

void
fbr_ops_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(fs->store);

	fbr_rlog(FBR_LOG_OP_DIR, "open req: %lu ino: %lu", request->id, ino);

	struct fbr_directory *stale;
	struct fbr_directory *directory = fbr_directory_from_inode(fs, ino, &stale);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		if (stale) {
			fbr_dindex_release(fs, &stale);
		}
		return;
	}

	struct fbr_dreader *reader = fbr_dreader_alloc(fs, directory);
	fbr_dreader_ok(reader);

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(reader);

	fi->cache_readdir = 1;

	fbr_fuse_reply_open(request, fi);

	if (stale) {
		fbr_dindex_release(fs, &stale);
	}
}

static void
_ops_diradd(struct fbr_request *request, struct fbr_dirbuffer *dbuf, struct fbr_file *file)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(dbuf);
	assert_dev(file);

	const char *filename = fbr_path_get_file(&file->path, NULL);

	fbr_rlog(FBR_LOG_OP_DIR, "read filename: '%s' inode: %lu", filename, file->inode);

	struct stat st;
	fbr_file_attr(fs, file, &st);

	fbr_dirbuffer_add(request, dbuf, filename, &st);
}

void
fbr_ops_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP_DIR, "read req: %lu ino: %lu size: %zu off: %ld", request->id, ino,
		size, off);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	if (reader->end) {
		fbr_rlog(FBR_LOG_OP_DIR, "read return: end");
		fbr_fuse_reply_buf(request, NULL, 0);
		return;
	}

	struct fbr_directory *directory = reader->directory;
	fbr_directory_ok(directory);

	struct fbr_dirbuffer dbuf;
	fbr_dirbuffer_init(&dbuf, size);

	if (!dbuf.full && !reader->read_dot) {
		fbr_file_ok(directory->file);

		struct stat st;
		fbr_file_attr(fs, directory->file, &st);

		fbr_dirbuffer_add(request, &dbuf, ".", &st);

		if (!dbuf.full) {
			reader->read_dot = 1;
		}
	}
	if (!dbuf.full && !reader->read_dotdot) {
		int do_release = 1;

		struct fbr_file *parent;
		if (directory->file->parent_inode) {
			parent = fbr_inode_take(fs, directory->file->parent_inode);
		} else {
			parent = directory->file;
			do_release = 0;
		}
		fbr_file_ok(parent);

		struct stat st;
		fbr_file_attr(fs, parent, &st);

		if (do_release) {
			fbr_inode_release(fs, &parent);
		}

		fbr_dirbuffer_add(request, &dbuf, "..", &st);

		if (!dbuf.full) {
			reader->read_dotdot = 1;
		}
	}

	if (dbuf.full) {
		fbr_rlog(FBR_LOG_OP_DIR, "read return: %zu", dbuf.pos);
		fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
		return;
	}

	struct fbr_path_name filedir;
	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);

	struct fbr_file_ptr *file_ptr;
	struct fbr_file_ptr *file_ptr_pos = reader->position;

	if (file_ptr_pos) {
		RB_FOREACH_FROM(file_ptr, fbr_filename_tree, file_ptr_pos) {
			fbr_file_ptr_ok(file_ptr);
			struct fbr_file *file = file_ptr->file;

			fbr_path_get_dir(&file->path, &filedir);
			assert_zero(fbr_path_name_cmp(&dirname, &filedir));

			_ops_diradd(request, &dbuf, file);

			if (dbuf.full) {
				break;
			}
		}
	} else {
		RB_FOREACH(file_ptr, fbr_filename_tree, &directory->filename_tree) {
			fbr_file_ptr_ok(file_ptr);
			struct fbr_file *file = file_ptr->file;

			fbr_path_get_dir(&file->path, &filedir);
			assert_zero(fbr_path_name_cmp(&dirname, &filedir));

			_ops_diradd(request, &dbuf, file);

			if (dbuf.full) {
				break;
			}
		}
	}

	if (dbuf.full) {
		assert_zero_dev(reader->end);

		reader->position = file_ptr;

		fbr_rlog(FBR_LOG_OP_DIR, "read return: %zu", dbuf.pos);
		fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);

		return;
	}

	reader->end = 1;

	fbr_rlog(FBR_LOG_OP_DIR, "read return: %zu", dbuf.pos);
	fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
}

void
fbr_ops_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP_DIR, " release req: %lu ino: %lu", request->id, ino);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	fbr_fuse_reply_err(request, 0);

	fbr_dreader_free(fs, reader);
}
