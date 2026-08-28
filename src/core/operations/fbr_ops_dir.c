/*
 * Copyright (c) 2024-2026 FiberFS LLC
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

	fbr_rlog(FBR_LOG_OP, "OPENDIR open req: %lu ino: %lu", request->id, ino);

	struct fbr_directory *directory = fbr_directory_from_inode(fs, ino);
	if (!directory) {
		fbr_fuse_reply_err(request, ENOTDIR);
		return;
	}

	struct fbr_dreader *reader = fbr_dreader_alloc(fs, directory);
	fbr_dreader_ok(reader);

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(reader);

	fi->cache_readdir = 1;

	fbr_fuse_reply_open(request, fi);
}

static void
_ops_diradd(struct fbr_request *request, struct fbr_dirbuffer *dbuf, struct fbr_file *file,
    off_t offset)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_dev(dbuf);
	assert_dev(file);
	assert_dev(offset)

	const char *filename = fbr_path_get_file(&file->path, NULL);

	struct stat st;
	fbr_file_attr(fs, file, &st);

	fbr_dirbuffer_add(request, dbuf, filename, &st, offset);
}

void
fbr_ops_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "READDIR req: %lu ino: %lu size: %zu off: %ld", request->id, ino,
		size, off);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	if (reader->end) {
		fbr_rlog(FBR_LOG_OP_DIR, "read return: end");
		fbr_fuse_reply_buf(request, NULL, 0);
		return;
	} else if (reader->offset != off || !off) {
		reader->offset = off;
		reader->file_pos = NULL;
	}

	struct fbr_directory *directory = reader->directory;
	fbr_directory_ok(directory);

	struct fbr_dirbuffer dbuf;
	fbr_dirbuffer_init(&dbuf, size);

	if (!dbuf.full && !reader->offset) {
		fbr_file_ok(directory->file);

		struct stat st;
		fbr_file_attr(fs, directory->file, &st);

		reader->offset++;

		fbr_dirbuffer_add(request, &dbuf, ".", &st, reader->offset);
	}
	if (!dbuf.full && reader->offset == 1) {
		int do_release = 0;

		struct fbr_file *parent;
		if (directory->file->parent_inode) {
			parent = fbr_inode_take(fs, directory->file->parent_inode);
			do_release = 1;
		} else {
			parent = directory->file;
		}

		reader->offset++;

		if (parent) {
			fbr_file_ok(parent);

			struct stat st;
			fbr_file_attr(fs, parent, &st);

			if (do_release) {
				fbr_inode_release(fs, &parent);
			}

			fbr_dirbuffer_add(request, &dbuf, "..", &st, reader->offset);
		}
	}

	if (dbuf.full) {
		fbr_rlog(FBR_LOG_OP_DIR, "read return: %zu", dbuf.pos);
		fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
		return;
	}

	struct fbr_file_ptr *file_ptr;
	assert_dev(reader->offset >= 2);

	if (reader->file_pos) {
		RB_FOREACH_FROM(file_ptr, fbr_filename_tree, reader->file_pos) {
			fbr_file_ptr_ok(file_ptr);
			struct fbr_file *file = file_ptr->file;

			reader->offset++;

			_ops_diradd(request, &dbuf, file, reader->offset);

			if (dbuf.full) {
				break;
			}
		}
	} else {
		off_t current = 2;

		RB_FOREACH(file_ptr, fbr_filename_tree, &directory->filename_tree) {
			fbr_file_ptr_ok(file_ptr);
			struct fbr_file *file = file_ptr->file;

			if (current < reader->offset) {
				current++;
				continue;
			}

			reader->offset++;
			current = reader->offset;

			_ops_diradd(request, &dbuf, file, reader->offset);

			if (dbuf.full) {
				break;
			}
		}
	}

	if (dbuf.full) {
		assert_zero_dev(reader->end);

		reader->offset--;
		reader->file_pos = file_ptr;

		fbr_rlog(FBR_LOG_OP_DIR, "read return: %zu offset: %ld", dbuf.pos, reader->offset);

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

	fbr_rlog(FBR_LOG_OP, "RELEASEDIR req: %lu ino: %lu", request->id, ino);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	fbr_fuse_reply_err(request, 0);

	fbr_dreader_free(fs, reader);
}
