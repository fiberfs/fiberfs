/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/operations/fbr_operations.h"
#include "core/store/fbr_store.h"
#include "cstore/fbr_cstore_io.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

int
_test_mkdir_flush(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffers,
    enum fbr_flush_flags flags)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	const char *filename = fbr_path_get_file(&file->path, NULL);
	if (!strcmp(filename, "test_flush_error")) {
		fbr_test_logs("FLUSH forcing error (EBUSY)");
		return EBUSY;
	}

	return fbr_directory_flush(fs, file, wbuffers, flags);
}

static const struct fbr_store_callbacks _TEST_MKDIR_CALLBACKS = {
	.directory_flush_f = _test_mkdir_flush,
	.index_write_f = fbr_cstore_index_root_write,
	.index_read_f = fbr_cstore_index_read,
	.index_delete_f = fbr_cstore_index_delete,
	.root_read_f = fbr_cstore_root_read
};

static void
_test_mkdir_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	fbr_fs_set_store(ctx->fs, &_TEST_MKDIR_CALLBACKS);
	fbr_test_cstore_init(fbr_test_get_ctx());

	fbr_test_fuse_root_alloc(ctx->fs);
}

static void
_test_mkdir_getattr(struct fbr_request *request, fuse_ino_t ino, struct fuse_file_info *fi)
{
	fbr_request_valid(request);

	fbr_test_logs("GETATTR req: %lu ino: %lu", request->id, ino);

	fbr_ops_getattr(request, ino, fi);
}

static void
_test_mkdir_lookup(struct fbr_request *request, fuse_ino_t parent, const char *name)
{
	fbr_request_valid(request);

	fbr_test_logs("LOOKUP req: %lu parent: %lu name: %s", request->id, parent, name);

	if (parent == FBR_INODE_ROOT) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_ops_lookup(request, parent, name);
}

static const struct fbr_fuse_callbacks _TEST_FS_MKDIR_CALLBACKS = {
	.init = _test_mkdir_init,
	.getattr = _test_mkdir_getattr,
	.lookup = _test_mkdir_lookup,
	.mkdir = fbr_ops_mkdir,
	.forget = fbr_ops_forget
};

void
fbr_cmd_mkdir_op_test_mount(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	char *mount = cmd->params[0].value;

	int ret = fbr_fuse_test_mount(ctx, mount, &_TEST_FS_MKDIR_CALLBACKS);
	assert_zero(ret);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "mkdir_op_test_mount done");
}

void
fbr_cmd_mkdir_test_fail(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	char *dirname = cmd->params[0].value;
	errno = 0;

	int ret = mkdir(dirname, S_IRWXU);
	assert(ret);

	fbr_test_logs("mkdir_test_fail(%s) ret: %d errno: %d (%s)", dirname,
		ret, errno, strerror(errno));
}

void
fbr_cmd_mkdir_test_remote(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	struct fbr_path_name dirname;
	fbr_path_name_init(&dirname, cmd->params[0].value);

	struct fbr_fs *fs_remote = fbr_test_fs_alloc();
	fbr_fs_ok(fs_remote);
	fbr_fs_set_store(fs_remote, &_TEST_MKDIR_CALLBACKS);

	struct fbr_directory *root = fbr_directory_load(fs_remote, FBR_DIRNAME_ROOT,
		FBR_INODE_ROOT);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	// add file on parent
	struct fbr_file *file = fbr_file_alloc_new(fs_remote, root, &dirname);
	assert_dev(file->state == FBR_FILE_INIT);
	file->mode = S_IFDIR;
	fbr_inode_add(fs_remote, file);

	// write new directory
	struct fbr_directory *new_directory;
	new_directory = fbr_directory_alloc(fs_remote, &dirname, file->inode);
	fbr_directory_ok(new_directory);
	assert(new_directory->state == FBR_DIRSTATE_LOADING);
	assert_zero(new_directory->generation);
	new_directory->generation = 1;
	struct fbr_index_data index_data;
	fbr_index_data_init(NULL, &index_data, new_directory, NULL, NULL, NULL, FBR_FLUSH_NONE);
	int ret = fbr_index_write(fs_remote, &index_data);
	assert_zero(ret);
	fbr_directory_set_state(fs_remote, new_directory, FBR_DIRSTATE_OK);
	fbr_index_data_free(&index_data);
	fbr_dindex_release(fs_remote, &new_directory);

	// flush parent
	assert(fs_remote->store);
	assert(fs_remote->store->directory_flush_f);
	ret = fs_remote->store->directory_flush_f(fs_remote, file, NULL, FBR_FLUSH_NONE);
	assert_zero(ret);
	assert(file->state == FBR_FILE_OK);

	fbr_dindex_release(fs_remote, &root);
	fbr_fs_free(fs_remote);

	fbr_test_logs("mkdir_test_remote: %s", dirname.name);
}
