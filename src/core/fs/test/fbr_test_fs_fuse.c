/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"

#include "fbr_test_fs_cmds.h"
#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

static DIR *_TEST_DIR;
static int _TEST_FD = -1;

static int _TEST_FS_DO_INIT;
static int _TEST_FS_ALLOW_CRASH;

static void
_test_fs_init_contents(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);

	fbr_test_logs("** INIT LOADING inode: %lu directory: '%.*s':%zu",
		directory->inode, (int)dirname.len, dirname.name, dirname.len);

	size_t depth = 0;

	while(dirname.len) {
		fbr_path_name_parent(&dirname, &dirname);
		depth++;
		assert(depth < 1000);
	}

	char name[128];
	struct fbr_path_name filename;
	struct fbr_file *file;
	int ret;

	if (!depth) {
		ret = snprintf(name, sizeof(name), "fiber_zero");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		file->mode = S_IFREG | 0444;
		file->size = 1025 * 125;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;

		ret = snprintf(name, sizeof(name), "fiber_zero1");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		file->mode = S_IFREG | 0444;
		file->size = 500;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;

		ret = snprintf(name, sizeof(name), "fiber_big");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		fbr_id_t id = fbr_id_gen();

		size_t s = 1024 * 512;

		fbr_body_chunk_add(file, id, s * 0, s);
		fbr_body_chunk_add(file, id, 10000, 100000);
		fbr_body_chunk_add(file, id, s * 0, s + 100);
		fbr_body_chunk_add(file, id, s * 1, s);

		file->mode = S_IFREG | 0444;
		file->size = 1024 * 1024;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;

		ret = snprintf(name, sizeof(name), "fiber_small");
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);
		fbr_file_ok(file);

		id = fbr_id_gen();

		file->mode = S_IFREG | 0444;
		file->size = 101;
		file->generation = fbr_id_gen();

		fbr_body_chunk_add(file, id, 0, 101);

		file->state = FBR_FILE_OK;
	}

	for (size_t i = 0; i < 4; i++) {
		mode_t fmode = S_IFREG | 0444;

		ret = snprintf(name, sizeof(name), "fiber_%zu%zu", depth, i + 1);
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);

		size_t chunks = (i + 1) * depth;
		file->generation = fbr_id_gen();
		file->mode = fmode;

		fbr_id_t id = fbr_id_gen();
		size_t offset = 0;
		for (size_t i = 0; i < chunks; i++) {
			if (!offset) {
				// even length will fail checksum
				fbr_body_chunk_add(file, id, 0, 11);
				fbr_body_chunk_add(file, id, 0, 10);
				fbr_body_chunk_add(file, id, 500, 607);
				fbr_body_chunk_add(file, id, 600, 500);
				fbr_body_chunk_add(file, id, 0, 601);
				fbr_body_chunk_add(file, id, 590, 551);
			} else {
				fbr_body_chunk_add(file, id, offset, 1001);
			}
			offset += 1001;
		}

		file->size = chunks * 1001;
		assert(offset == file->size);

		file->state = FBR_FILE_OK;
	}

	for (size_t i = 0; i < 4; i++) {
		if (depth > 4) {
			break;
		}

		mode_t fmode = S_IFDIR | 0555;

		ret = snprintf(name, sizeof(name), "fiber_dir%zu%zu", depth, i + 1);
		assert((size_t)ret < sizeof(name));

		fbr_path_name_init(&filename, name);

		file = fbr_file_alloc(fs, directory, &filename);

		file->mode = fmode;
		file->generation = fbr_id_gen();
		file->state = FBR_FILE_OK;
	}

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
}

static struct fbr_directory *
_test_fs_init_directory(struct fbr_fs *fs, const struct fbr_path_name *dirname, fbr_inode_t inode)
{
	fbr_fs_ok(fs);
	assert(dirname);
	assert(inode);

	if (!_TEST_FS_DO_INIT) {
		return NULL;
	}

	struct fbr_directory *directory = NULL;

	if (inode == FBR_INODE_ROOT) {
		assert_zero(dirname->len);

		directory = fbr_directory_root_alloc(fs);
	} else {
		assert(dirname->len);

		directory = fbr_directory_alloc(fs, dirname, inode);
	}

	if (directory->state == FBR_DIRSTATE_LOADING) {
		_test_fs_init_contents(fs, directory);
	} else {
		fbr_test_logs("** INIT OK inode: %lu directory: '%.*s':%zu",
			directory->inode, (int)dirname->len, dirname->name, dirname->len);
	}

	assert(directory->state == FBR_DIRSTATE_OK);

	return directory;
}

static void
_test_fs_chunk_gen(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	char buf[PATH_MAX];
	const char *fullpath = fbr_path_get_full(&file->path, NULL, buf, sizeof(buf));

	fbr_test_logs("** FETCH chunk: offset: %zu length: %zu splice: %d path: %s",
		chunk->offset, chunk->length, chunk->fd_splice_ok, fullpath);

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	size_t counter = chunk->offset;

	if (chunk->length % 2 == 0 && chunk->length < 1024) {
		counter++;
	}

	for (size_t i = 0; i < chunk->length; i++) {
		chunk->data[i] = (counter % 10) + '0';
		counter++;
	}

	chunk->state = FBR_CHUNK_READY;

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, chunk->length);
}

static const struct fbr_store_callbacks _TEST_FS_STORE_CALLBACKS = {
	.fetch_chunk_f = _test_fs_chunk_gen
};

static void
_test_fs_fuse_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	conn->want |= FUSE_CAP_SPLICE_WRITE;
	conn->want |= FUSE_CAP_SPLICE_MOVE;

	fbr_fs_set_store(ctx->fs, &_TEST_FS_STORE_CALLBACKS);

	_TEST_FS_DO_INIT = 1;
}

void
fbr_test_fs_fuse_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	(void)fi;

	fbr_test_logs("GETATTR ino: %lu", ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_file_ok(file);

	struct stat st;
	fbr_file_attr(file, &st);

	fbr_inode_release(fs, &file);
	assert_zero_dev(file);

	fbr_fuse_reply_attr(request, &st, fbr_fs_dentry_ttl(fs));
}

void
fbr_test_fs_fuse_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("LOOKUP parent: %lu name: %s", parent, name);

	if (_TEST_FS_ALLOW_CRASH && !strcmp(name, "__CRASH")) {
		fbr_ABORT("__CRASH triggered!");
	}

	struct fbr_file *parent_file = fbr_inode_take(fs, parent);

	if (!parent_file || parent_file->state == FBR_FILE_EXPIRED) {
		fbr_fuse_reply_err(request, ENOTDIR);

		if (parent_file) {
			fbr_inode_release(fs, &parent_file);
		}
		assert_zero_dev(parent_file);

		return;
	}

	struct fbr_path_name parent_dirname;
	char buf[PATH_MAX];
	fbr_path_get_full(&parent_file->path, &parent_dirname, buf, sizeof(buf));

	fbr_test_logs("** LOOKUP found parent_file: '%.*s':%zu (inode: %lu)",
		(int)parent_dirname.len, parent_dirname.name, parent_dirname.len,
		parent_file->inode);

	struct fbr_directory *directory = fbr_dindex_take(fs, &parent_dirname, 0);
	struct fbr_directory *stale_directory = NULL;

	if (directory && directory->inode > parent_file->inode) {
		fbr_test_logs("** LOOKUP parent: %lu found newer dir_inode: %lu (return error)",
			parent_file->inode, directory->inode);

		fbr_fuse_reply_err(request, ENOTDIR);

		fbr_inode_release(fs, &parent_file);
		fbr_dindex_release(fs, &directory);

		return;
	} else if (directory && directory->inode < parent_file->inode) {
		fbr_test_logs("** LOOKUP parent: %lu mismatch dir_inode: %lu (will make new)",
			parent_file->inode, directory->inode);
		stale_directory = directory;
		directory = NULL;
	}

	if (!directory) {
		directory = _test_fs_init_directory(fs, &parent_dirname, parent_file->inode);

		if (!directory) {
			fbr_fuse_reply_err(request, EIO);

			fbr_inode_release(fs, &parent_file);

			if (stale_directory) {
				fbr_dindex_release(fs, &stale_directory);
				assert_zero_dev(stale_directory);
			}

			return;
		}

		assert(directory->inode == parent_file->inode);
	}

	fbr_directory_ok(directory);

	fbr_inode_release(fs, &parent_file);
	assert_zero_dev(parent_file);

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);
	fbr_test_logs("** LOOKUP found directory: '%s' (inode: %lu)",
		dirname.name, directory->inode);

	size_t name_len = strlen(name);
	struct fbr_file *file = fbr_directory_find_file(directory, name, name_len);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);

		fbr_dindex_release(fs, &directory);
		assert_zero_dev(directory);

		if (stale_directory) {
			fbr_dindex_release(fs, &stale_directory);
			assert_zero_dev(stale_directory);
		}

		return;
	}

	fbr_file_ok(file);

	const char *fullname = fbr_path_get_full(&file->path, NULL, buf, sizeof(buf));
	fbr_test_logs("** LOOKUP found file: '%s' (inode: %lu)", fullname, file->inode);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);
	assert(name_len == filename.len);
	assert_zero(strcmp(name, filename.name));

	struct fuse_entry_param entry;
	fbr_ZERO(&entry);
	entry.attr_timeout = fbr_fs_dentry_ttl(fs);
	entry.entry_timeout = fbr_fs_dentry_ttl(fs);
	entry.ino = file->inode;
	fbr_file_attr(file, &entry.attr);

	fbr_inode_add(fs, file);

	fbr_fuse_reply_entry(request, &entry);

	fbr_dindex_release(fs, &directory);
	assert_zero_dev(directory);

	if (stale_directory) {
		fbr_dindex_release(fs, &stale_directory);
		assert_zero_dev(stale_directory);
	}
}

void
fbr_test_fs_fuse_opendir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("OPENDIR ino: %lu", ino);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file || file->state == FBR_FILE_EXPIRED) {
		fbr_fuse_reply_err(request, ENOENT);

		if (file) {
			fbr_inode_release(fs, &file);
		}
		assert_zero_dev(file);

		return;
	}

	struct fbr_path_name dirname;
	char buf[PATH_MAX];
	fbr_path_get_full(&file->path, &dirname, buf, sizeof(buf));

	fbr_test_logs("** OPENDIR directory: '%.*s':%zu",
		(int)dirname.len, dirname.name, dirname.len);

	struct fbr_directory *directory = fbr_dindex_take(fs, &dirname, 0);
	struct fbr_directory *stale_directory = NULL;

	if (directory && directory->inode > file->inode) {
		fbr_test_logs("** OPENDIR inode: %lu found newer dir_inode: %lu (return error)",
			file->inode, directory->inode);

		fbr_fuse_reply_err(request, ENOENT);

		fbr_inode_release(fs, &file);
		fbr_dindex_release(fs, &directory);

		return;
	} else if (directory && directory->inode < file->inode) {
		fbr_test_logs("** OPENDIR inode: %lu mismatch dir_inode: %lu (will make new)",
			file->inode, directory->inode);
		stale_directory = directory;
		directory = NULL;
	}

	if (!directory) {
		directory = _test_fs_init_directory(fs, &dirname, file->inode);

		if (!directory) {
			fbr_fuse_reply_err(request, EIO);

			fbr_inode_release(fs, &file);
			assert_zero_dev(file);

			if (stale_directory) {
				fbr_dindex_release(fs, &stale_directory);
				assert_zero_dev(stale_directory);
			}

			return;
		}

		assert(directory->inode == file->inode);
	}

	fbr_directory_ok(directory);

	fbr_inode_release(fs, &file);
	assert_zero_dev(file);

	struct fbr_dreader *reader = fbr_dreader_alloc(fs, directory);
	fbr_dreader_ok(reader);

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(reader);

	fi->cache_readdir = 1;

	fbr_fuse_reply_open(request, fi);

	if (stale_directory) {
		fbr_dindex_release(fs, &stale_directory);
		assert_zero_dev(stale_directory);
	}
}

void
fbr_test_fs_fuse_readdir(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("READDIR ino: %lu size: %zu off: %ld", ino, size, off);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	if (reader->end) {
		fbr_test_logs("READDIR return: end");
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
		fbr_file_attr(directory->file, &st);

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
		fbr_file_attr(parent, &st);

		if (do_release) {
			fbr_inode_release(fs, &parent);
		}

		fbr_dirbuffer_add(request, &dbuf, "..", &st);

		if (!dbuf.full) {
			reader->read_dotdot = 1;
		}
	}

	if (dbuf.full) {
		fbr_test_logs("READDIR return: %zu", dbuf.pos);
		fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
		return;
	}

	struct fbr_path_name dirname;
	fbr_directory_name(directory, &dirname);

	struct fbr_file *file = reader->position;

	TAILQ_FOREACH_FROM(file, &directory->file_list, file_entry) {
		fbr_file_ok(file);

		struct fbr_path_name filedir;
		fbr_path_get_dir(&file->path, &filedir);
		assert_zero(fbr_path_name_cmp(&dirname, &filedir));

		const char *filename = fbr_path_get_file(&file->path, NULL);

		fbr_test_logs("READDIR filename: '%s' inode: %lu", filename, file->inode);

		struct stat st;
		fbr_file_attr(file, &st);

		fbr_dirbuffer_add(request, &dbuf, filename, &st);

		reader->position = file;

		if (dbuf.full) {
			fbr_test_logs("READDIR return: %zu", dbuf.pos);
			fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
			return;
		}
	}

	reader->end = 1;

	fbr_test_logs("READDIR return: %zu", dbuf.pos);
	fbr_fuse_reply_buf(request, dbuf.buffer, dbuf.pos);
}

void
fbr_test_fs_fuse_releasedir(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("RELEASEDIR ino: %lu", ino);

	struct fbr_dreader *reader = fbr_fh_dreader(fi->fh);

	fbr_fuse_reply_err(request, 0);

	fbr_dreader_free(fs, reader);
}

static void
_test_fs_fuse_open(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("OPEN ino: %lu flags: %d", ino, fi->flags);

	struct fbr_file *file = fbr_inode_take(fs, ino);

	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	} else if (!S_ISREG(file->mode)) {
		fbr_inode_release(fs, &file);
		assert_zero_dev(file);

		fbr_fuse_reply_err(request, EISDIR);
		return;
	} else if (fi->flags & O_WRONLY || fi->flags & O_RDWR) {
		fbr_inode_release(fs, &file);
		assert_zero_dev(file);

		fbr_test_logs("** OPEN detected write");

		fbr_fuse_reply_err(request, EROFS);
		return;
	}

	struct fbr_fio *fio = fbr_fio_alloc(fs, file);
	fbr_fio_ok(fio);

	fio->read_only = 1;

	assert_zero_dev(fi->fh);
	fi->fh = fbr_fs_int64(fio);

	fi->keep_cache = 1;

	fbr_fuse_reply_open(request, fi);
}

void
fbr_test_fs_fuse_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("READ ino: %lu off: %ld size: %zu flags: %d", ino, off, size, fi->flags);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_take(fio);
	fbr_file_ok(fio->file);

	request->locked = 1;

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, off, size);

	if (!vector) {
		if (fio->error) {
			fbr_fuse_reply_err(request, EIO);
		} else {
			fbr_fuse_reply_buf(request, NULL, 0);
		}
	} else {
		fbr_chunk_list_ok(vector->chunks);
		assert(vector->bufvec);

		fbr_test_logs("** READ chunks: %u bufvecs: %zu",
			vector->chunks->length, vector->bufvec->count);
		fbr_fs_stat_add_count(&fs->stats.read_bytes, vector->size);

		fbr_fuse_reply_data(request, vector->bufvec, FUSE_BUF_SPLICE_MOVE);

		fbr_fio_vector_free(fs, fio, vector);
	}

	fbr_fio_release(fs, fio);
}

static void
_test_fs_fuse_release(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("RELEASE ino: %lu flags: %d", ino, fi->flags);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_release(fs, fio);

	fbr_fuse_reply_err(request, 0);
}

void
fbr_test_fs_fuse_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("FORGET ino: %lu nlookup: %lu", ino, nlookup);

	fbr_inode_forget(fs, ino, nlookup);
	fbr_fuse_reply_none(request);
}

void
fbr_test_fs_fuse_forget_multi(struct fbr_request *request, size_t count,
    struct fuse_forget_data *forgets)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_test_logs("FORGET_MULTI count: %zu", count);

	for (size_t i = 0; i < count; i++) {
		fbr_test_logs("FORGET_MULTI ino: %lu nlookup: %lu",
			forgets[i].ino, forgets[i].nlookup);

		fbr_inode_forget(fs, forgets[i].ino, forgets[i].nlookup);
	}

	fbr_fuse_reply_none(request);
}

static const struct fbr_fuse_callbacks _TEST_FS_FUSE_CALLBACKS = {
	.init = _test_fs_fuse_init,

	.getattr = fbr_test_fs_fuse_getattr,
	.lookup = fbr_test_fs_fuse_lookup,

	.opendir = fbr_test_fs_fuse_opendir,
	.readdir = fbr_test_fs_fuse_readdir,
	.releasedir = fbr_test_fs_fuse_releasedir,

	.open = _test_fs_fuse_open,
	.read = fbr_test_fs_fuse_read,
	.release = _test_fs_fuse_release,

	.forget = fbr_test_fs_fuse_forget,
	.forget_multi = fbr_test_fs_fuse_forget_multi
};

void
fbr_cmd_fs_test_fuse_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	int ret = fbr_fuse_test_mount(ctx, cmd->params[0].value, &_TEST_FS_FUSE_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", cmd->params[0].value);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", cmd->params[0].value);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	fs->logger = fbr_fs_test_logger;
}

void
fbr_cmd_fs_test_fuse_init_root(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_fuse_mounted(fuse_ctx);
	struct fbr_fs *fs = fuse_ctx->fs;
	fbr_fs_ok(fs);

	struct fbr_directory *root = _test_fs_init_directory(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT);
	fbr_dindex_release(fs, &root);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs root initialized");
}

void
fbr_cmd_fs_test_allow_crash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_TEST_FS_ALLOW_CRASH = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs allow crash %d", _TEST_FS_ALLOW_CRASH);
}

void
fbr_cmd__fs_test_take_dir(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_ASSERT(_TEST_DIR == NULL, "_TEST_DIR exists");

	char *dirname = cmd->params[0].value;

	_TEST_DIR = opendir(dirname);
	fbr_test_ASSERT(_TEST_DIR, "opendir failed for %s", dirname);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "dir handle aquired %s", dirname);
}

void
fbr_cmd__fs_test_release_dir(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_ASSERT(_TEST_DIR, "_TEST_DIR invalid");

	int ret = closedir(_TEST_DIR);
	fbr_test_ERROR(ret, "closedir failed %d", ret);

	_TEST_DIR = NULL;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "dir handle released");
}

void
fbr_cmd__fs_test_take_file(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 1);

	fbr_test_ASSERT(_TEST_FD == -1, "_TEST_FD exists");

	char *filename = cmd->params[0].value;

	_TEST_FD = open(filename, O_RDONLY);
	fbr_test_ASSERT(_TEST_FD >= 0, "open failed for %s", filename);

	uint8_t buf[100];
	ssize_t bytes = read(_TEST_FD, buf, sizeof(buf));
	fbr_test_ASSERT(bytes >= 0, "read error");

	for (ssize_t i = 0; i < bytes; i++) {
		fbr_test_ASSERT(buf[i] == '\0', "bad bytes in read");
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fd handle aquired %s (%zd)", filename, bytes);
}

void
fbr_cmd__fs_test_release_file(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_ERROR(fbr_test_is_valgrind(), "cannot be used with valgrind");
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_ASSERT(_TEST_FD >= 0, "_TEST_FD invalid");

	ssize_t bytes, total = 0;

	do {
		uint8_t buf[100];
		bytes = read(_TEST_FD, buf, sizeof(buf));
		fbr_test_ASSERT(bytes >= 0, "read error");

		for (ssize_t i = 0; i < bytes; i++) {
			fbr_test_ASSERT(buf[i] == '\0', "bad bytes in read");
		}

		total += bytes;
	} while (bytes > 0);

	int ret = close(_TEST_FD);
	fbr_test_ERROR(ret, "closedir failed %d", ret);

	_TEST_FD = -1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fd handle released (%zd)", total);
}
