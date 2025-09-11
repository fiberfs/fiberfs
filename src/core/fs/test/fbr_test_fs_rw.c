/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_request.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_io.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

extern int _DEBUG_WBUFFER_ALLOC_SIZE;

static int
_test_fs_rw_directory_flush(struct fbr_fs *fs, struct fbr_file *file,
    struct fbr_wbuffer *wbuffers, enum fbr_flush_flags flags)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_file *parent = fbr_inode_take(fs, file->parent_inode);
	fbr_ASSERT(parent, "parent %lu missing", file->parent_inode);
	fbr_file_ok(parent);

	struct fbr_path_name dirname;
	char buf[FBR_PATH_MAX];
	fbr_path_get_full(&parent->path, &dirname, buf, sizeof(buf));

	const char *filename = fbr_path_get_file(&file->path, NULL);

	struct fbr_directory *directory = fbr_dindex_take(fs, &dirname, 1);
	fbr_ASSERT(directory, "directory '%s' missing", dirname.name);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_OK);

	fbr_test_logs("RW_FLUSH directory: '%s' (%lu) file: '%s' (%lu)", dirname.name,
		directory->generation, filename, file->generation);

	struct fbr_directory *new_directory = fbr_directory_alloc(fs, &dirname, directory->inode);
	fbr_directory_ok(new_directory);
	fbr_ASSERT(new_directory->state == FBR_DIRSTATE_LOADING, "new_directory isnt LOADING");

	fbr_directory_copy(fs, new_directory, directory);

	new_directory->generation++;

	struct fbr_directory *previous = new_directory->previous;
	if (!previous) {
		previous = directory;
	}

	fbr_file_LOCK(fs, file);

	if (file->state == FBR_FILE_INIT) {
		file->state = FBR_FILE_OK;
		file->generation = 1;
		fbr_directory_add_file(fs, new_directory, file);
	} else {
		file->generation++;
	}

	struct fbr_index_data index_data;
	fbr_index_data_init(fs, &index_data, new_directory, previous, file, wbuffers, flags);

	int ret = fbr_index_write(fs, &index_data);
	if (ret) {
		fbr_test_logs("RW_FLUSH fbr_index_write(new_directory) failed (%d %s)",
			ret, strerror(ret));
		fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_ERROR);
	} else {
		fbr_directory_set_state(fs, new_directory, FBR_DIRSTATE_OK);
	}

	fbr_file_UNLOCK(file);

	fbr_index_data_free(&index_data);

	// Safe to call within flush
	fbr_dindex_release(fs, &directory);
	fbr_dindex_release(fs, &new_directory);
	fbr_inode_release(fs, &parent);

	return ret;
}

static const struct fbr_store_callbacks _TEST_FS_RW_STORE_CALLBACKS = {
	.directory_load_f = fbr_directory_load,
	.chunk_read_f = fbr_cstore_async_chunk_read,
	.chunk_delete_f = fbr_cstore_chunk_delete,
	.wbuffer_write_f = fbr_cstore_async_wbuffer_write,
	.directory_flush_f = _test_fs_rw_directory_flush,
	.index_write_f = fbr_cstore_index_root_write,
	.index_read_f = fbr_cstore_index_read,
	.index_delete_f = fbr_cstore_index_delete,
	.root_read_f = fbr_cstore_root_read
};

static void
_test_fs_rw_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	fbr_fs_set_store(ctx->fs, &_TEST_FS_RW_STORE_CALLBACKS);

	fbr_test_cstore_init(fbr_test_get_ctx());

	//conn->max_readahead
	//conn->max_background
	//FUSE_CAP_POSIX_ACL
	//FUSE_CAP_HANDLE_KILLPRIV

	conn->want |= FUSE_CAP_SPLICE_WRITE;
	conn->want |= FUSE_CAP_SPLICE_MOVE;
	conn->want &= ~FUSE_CAP_SPLICE_READ;

	// TODO fuse said this breaks distributed append if enabled
	conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;

	struct fbr_directory *root = fbr_directory_root_alloc(ctx->fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	root->generation++;
	assert(root->generation == 1);

	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, root, NULL, NULL, NULL, FBR_FLUSH_NONE);

	int ret = fbr_index_write(ctx->fs, &index_data);
	if (ret) {
		fbr_test_logs("INIT fbr_index_write(root) failed");
		fbr_directory_set_state(ctx->fs, root, FBR_DIRSTATE_ERROR);
		ctx->error = 1;
	} else {
		fbr_directory_set_state(ctx->fs, root, FBR_DIRSTATE_OK);
	}

	fbr_index_data_free(&index_data);

	struct fbr_path_name dirpath;
	fbr_directory_name(root, &dirpath);
	fbr_id_t root_id = fbr_cstore_root_read(ctx->fs, &dirpath);

	fbr_test_logs("INIT fbr_cstore_root_read(): %lu", root_id);
	fbr_ASSERT(root_id == root->version, "root version mismatch, found %lu, expected %lu",
		root_id, root->version);

	fbr_dindex_release(ctx->fs, &root);
}

static const struct fbr_fuse_callbacks _TEST_FS_RW_CALLBACKS = {
	.init = _test_fs_rw_init,

	.getattr = fbr_ops_getattr,
	.lookup = fbr_ops_lookup,

	.mkdir = fbr_ops_mkdir,

	.opendir = fbr_ops_opendir,
	.readdir = fbr_ops_readdir,
	.releasedir = fbr_ops_releasedir,

	.open = fbr_ops_open,
	.create = fbr_ops_create,
	.read = fbr_ops_read,
	.write = fbr_ops_write,
	.flush = fbr_ops_flush,
	.release = fbr_ops_release,
	.fsync = fbr_ops_fsync,

	.forget = fbr_ops_forget,
	.forget_multi = fbr_ops_forget_multi
};

void
fbr_cmd_fs_test_rw_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *mount = cmd->params[0].value;

	int ret = fbr_fuse_test_mount(ctx, mount, &_TEST_FS_RW_CALLBACKS);
	fbr_test_ERROR(ret, "fs fuse mount failed: %s", mount);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs test_fuse mounted: %s", mount);
}

void
fbr_cmd_fs_test_rw_buffer_size(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long value = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ASSERT(value > 0, "Buffer size needs to be greater than 0");

	_DEBUG_WBUFFER_ALLOC_SIZE = value;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "fs buffer_size: %d", _DEBUG_WBUFFER_ALLOC_SIZE);
}
