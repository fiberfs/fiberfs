/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/iocmd/fbr_cmd.h"
#include "core/iocmd/fbr_iocmd.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"


void
fbr_cmd_iocmd_ping(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *path = cmd->params[0].value;
	double timing;

	int ret = fbr_cmd_ping(path, &timing);
	fbr_test_ERROR(ret, "fbr_cmd_ping() failed: %d", ret);

	fbr_test_logs("iocmd_ping done: %s timing: %f", path, timing);
}

void
fbr_cmd_iocmd_import(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count >= 1 && cmd->param_count <= 2);
	fbr_test_ERROR_string(cmd->params[0].value);

	const char *path = cmd->params[0].value;
	int overwrite = 0;

	if (cmd->param_count > 1) {
		long value = fbr_test_parse_long(cmd->params[1].value);
		if (value > 0) {
			overwrite = 1;
		}
	}

	int ret = fbr_cmd_import(path, overwrite);
	fbr_test_ERROR(ret, "fbr_cmd_import() failed: %d", ret);

	fbr_test_logs("iocmd_import done: %s", path);
}

void
fbr_cmd_iocmd_import_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	assert_zero(fbr_test_is_valgrind());

	const char *path = cmd->params[0].value;

	int ret = fbr_cmd_import(path, 0);
	fbr_test_ASSERT(ret, "fbr_cmd_import() did not fail");

	fbr_test_logs("iocmd_import_error done: %s %d %s", path, ret, strerror(ret));
}

void
fbr_cmd_iocmd_merge(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	const char *path = cmd->params[0].value;

	int ret = fbr_cmd_merge(path);
	fbr_test_ERROR(ret, "fbr_cmd_merge() failed: %d", ret);

	fbr_test_logs("iocmd_merge done: %s", path);
}

#define _TEST_IMPORT_FILES		25
#define _TEST_IMPORT_FILE_SIZE		(10L * 1024 * 1024 * 1024)

static int
_test_import_size(struct fbr_fs *fs, struct fbr_cstore_url *url, unsigned long *size)
{
	fbr_fs_ok(fs);
	assert(url);
	assert(size);

	fbr_test_logs("** url: '%s'", url->value);

	*size = _TEST_IMPORT_FILE_SIZE;

	return 0;
}

static void
_test_import_file(struct fbr_fs *fs, unsigned int count)
{
	fbr_fs_ok(fs);

	fbr_test_logs("** import: %d", count);

	struct fbr_file *root_file = fbr_inode_take(fs, FBR_INODE_ROOT);
	fbr_file_ok(root_file);

	struct fbr_iocmd_import io_import;
	fbr_zero(&io_import);
	io_import.magic = FBR_IOCMD_IMPORT_MAGIC;
	io_import.filename.path.length = fbr_bprintf(io_import.filename.data, "file_%d", count);

	int error = fbr_iocmd_import(fs, root_file, FBR_IOCMD_IMPORT_REQ, &io_import, NULL);
	assert_zero(error);

	fbr_inode_release(fs, &root_file);
}

void
fbr_cmd_iocmd_import_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** Init");

	fbr_test_random_seed();
	fbr_test_fuse_mock(ctx);

	struct fbr_store_callbacks import_callbacks;
	memcpy(&import_callbacks, FBR_CSTORE_DEFAULT_CALLBACKS, sizeof(import_callbacks));
	import_callbacks.external_file_size = _test_import_size;

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, &import_callbacks);
	fbr_test_cstore_bind_new(fs);

	struct fbr_request *request = fbr_test_request_mock();
	fbr_fuse_detached(request->fuse_ctx);
	fbr_request_valid(request);

	fbr_test_logs("*** Alloc root");

	fbr_test_fs_root_alloc(fs);

	fbr_test_logs("*** Import files");

	unsigned int max = _TEST_IMPORT_FILES;
	if (fbr_test_is_valgrind()) {
		max = 5;
	}

	for (unsigned int i = 1; i <= max; i++) {
		_test_import_file(fs, i);
	}

	fbr_test_logs("*** Read fresh index");

	fbr_fs_release_all(fs, 0);
	fbr_test_fs_wait(fs);

	struct fbr_directory *root = fbr_directory_from_inode(fs, FBR_INODE_ROOT);
	fbr_directory_ok(root);
	assert(root->file_count == max);

	fbr_dindex_release(fs, &root);

	fbr_test_logs("*** Cleanup fs");

	fbr_fs_release_all(fs, 1);

	fbr_test_cstore_wait(fs->cstore);
	fbr_test_fs_wait(fs);

	assert_zero(fs->stats.directories);
	assert_zero(fs->stats.directories_dindex);
	assert_zero(fs->stats.directory_refs);
	assert_zero(fs->stats.files);
	assert_zero(fs->stats.files_inodes);
	assert_zero(fs->stats.file_refs);

	fbr_request_free(request);
	fbr_fs_free(fs);

	fbr_test_logs("iocmd_import_test done");
}
