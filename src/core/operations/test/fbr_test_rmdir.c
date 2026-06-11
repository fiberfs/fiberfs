/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <errno.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_request.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

void
fbr_cmd_rmdir_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (fbr_test_can_vfork(ctx)) {
		fbr_test_fork(ctx, cmd);
		return;
	}

	const char *filename = cmd->params[0].value;

	int ret = rmdir(filename);
	fbr_ASSERT(ret, "rmdir() didnt fail");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sys_rmdir_error() passed %s (%d)",
		strerror(errno), ret);
}

static struct fbr_request *
_rmdir_2fs_request_mock(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_request *request = fbr_test_request_mock();
	fbr_fuse_detached(request->fuse_ctx);
	request->fs = fs;
	fbr_request_valid(request);
	assert_zero(request->error);

	return request;
}

void
fbr_cmd_rmdir_2fs_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_fuse_mock(ctx);

	struct fbr_fs *fs_1 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_1);
	fbr_test_cstore_bind_new(fs_1);
	fbr_fs_set_store(fs_1, FBR_CSTORE_DEFAULT_CALLBACKS);

	struct fbr_fs *fs_2 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_2);
	fbr_test_cstore_bind(fs_2, 0);
	fbr_fs_set_store(fs_2, FBR_CSTORE_DEFAULT_CALLBACKS);

	assert(fbr_test_cstore_count(ctx) == 1);

	struct fbr_path_name dirpath;
	fbr_path_name_init(&dirpath, "test_dir");
	struct fbr_path_name testfile;
	fbr_path_name_init(&testfile, "SomeFile.txt");

	fbr_test_logs("*** Setup test_dir on fs_1");

	fbr_test_fs_root_alloc(fs_1);

	struct fbr_request *request = _rmdir_2fs_request_mock(fs_1);
	fbr_ops_mkdir(request, FBR_INODE_ROOT, dirpath.name, 0);
	assert_zero(request->error);
	fbr_request_free(request);

	fbr_test_logs("*** Read test_dir on fs_2");

	fbr_directory_root_inode_init(fs_2);

	request = _rmdir_2fs_request_mock(fs_2);
	fbr_ops_lookup(request, FBR_INODE_ROOT, dirpath.name);
	assert_zero(request->error);
	fbr_request_free(request);

	fbr_test_logs("*** Make file on test_dir on fs_2");

	struct fbr_directory *root_fs2 = fbr_dindex_take(fs_2, FBR_DIRNAME_ROOT, 0);
	fbr_directory_ok(root_fs2);
	assert(root_fs2->state == FBR_DIRSTATE_OK);

	struct fbr_file *dirfile_fs2 = fbr_directory_find_file(root_fs2, dirpath.name,
		dirpath.length);
	fbr_file_ok(dirfile_fs2);
	assert(dirfile_fs2->state == FBR_FILE_OK);
	fbr_inode_add(fs_2, dirfile_fs2);

	struct fbr_directory *dir_fs2 = fbr_directory_get(fs_2, &dirpath, dirfile_fs2->inode);
	fbr_directory_ok(dir_fs2);
	assert(dir_fs2->state == FBR_DIRSTATE_OK);

	struct fuse_file_info fi;
	fbr_zero(&fi);
	fi.flags = O_CREAT | O_WRONLY | O_APPEND;

	request = _rmdir_2fs_request_mock(fs_2);

	fbr_ops_create(request, dir_fs2->inode, testfile.name, S_IFREG, &fi);
	assert_zero(request->error);
	struct fbr_fio *fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);
	fbr_ops_write(request, fio->file->inode, "rmdir!", 7, 0, &fi);
	assert_zero(request->error);
	fbr_ops_release(request, fio->file->inode, &fi);
	assert_zero(request->error);

	fbr_request_free(request);
	fbr_dindex_release(fs_2, &root_fs2);
	fbr_dindex_release(fs_2, &dir_fs2);
	fbr_inode_release(fs_2, &dirfile_fs2);

	fbr_test_logs("*** Cleanup fs_1");

	fbr_test_sleep_ms(20);

	fbr_fs_release_all(fs_1, 1);

	fbr_test_fs_stats(fs_1);
	fbr_test_fs_inodes_debug(fs_1);
	fbr_test_fs_dindex_debug(fs_1);

	fbr_test_ERROR(fs_1->stats.directories, "non zero");
	fbr_test_ERROR(fs_1->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_1->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_1->stats.files, "non zero");
	fbr_test_ERROR(fs_1->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_1->stats.file_refs, "non zero");

	fbr_fs_free(fs_1);

	fbr_test_logs("*** Cleanup fs_2");

	fbr_fs_release_all(fs_2, 1);

	fbr_test_fs_stats(fs_2);
	fbr_test_fs_inodes_debug(fs_2);
	fbr_test_fs_dindex_debug(fs_2);

	fbr_test_cstore_debug(fs_2->cstore);

	fbr_test_ERROR(fs_2->stats.directories, "non zero");
	fbr_test_ERROR(fs_2->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_2->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_2->stats.files, "non zero");
	fbr_test_ERROR(fs_2->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_2->stats.file_refs, "non zero");

	fbr_fs_free(fs_2);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "merge_2fs_test done");
}
