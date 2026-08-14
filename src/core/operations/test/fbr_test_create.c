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
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

static struct fbr_request *
_create_2fs_request_mock(struct fbr_fs *fs)
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
fbr_cmd_create_2fs_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_fuse_mock(ctx);
	fbr_test_request_pool_register(ctx);

	struct fbr_fs *fs_1 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_1);
	fbr_test_cstore_bind_new(fs_1);
	fbr_fs_set_store(fs_1, FBR_CSTORE_DEFAULT_CALLBACKS);

	struct fbr_fs *fs_2 = fbr_test_fs_alloc();
	fbr_fs_ok(fs_2);
	fbr_test_cstore_bind(fs_2, 0);
	fbr_fs_set_store(fs_2, FBR_CSTORE_DEFAULT_CALLBACKS);

	assert(fbr_test_cstore_count(ctx) == 1);

	struct fbr_path_name testfile;
	fbr_path_name_init(&testfile, "test_create.log");

	fbr_rlog(FBR_LOG_TEST, "*** Create root on fs_1");

	fbr_test_fs_root_alloc(fs_1);

	fbr_rlog(FBR_LOG_TEST, "*** Create testfile on fs_1");

	struct fbr_request *request = _create_2fs_request_mock(fs_1);

	struct fuse_file_info fi;
	fbr_zero(&fi);
	fi.flags = O_CREAT | O_WRONLY;
	fbr_ops_create(request, FBR_INODE_ROOT, testfile.name, S_IFREG, &fi);
	assert_zero(request->error);

	struct fbr_fio *fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);
	fbr_ops_write(request, fio->file->inode, "hello.", 6, 0, &fi);
	assert_zero(request->error);

	fbr_ops_release(request, fio->file->inode, &fi);
	assert_zero(request->error);

	fbr_request_free(request);

	fbr_rlog(FBR_LOG_TEST, "*** Read root on fs_2");

	fbr_directory_root_inode_init(fs_2);

	struct fbr_directory *root_fs2 = fbr_directory_from_inode(fs_2, FBR_INODE_ROOT);
	fbr_directory_ok(root_fs2);
	assert(root_fs2->state == FBR_DIRSTATE_OK);
	fbr_dindex_release(fs_2, &root_fs2);

	fbr_rlog(FBR_LOG_TEST, "*** Create testfile on fs_2");

	request = _create_2fs_request_mock(fs_2);

	fbr_zero(&fi);
	fi.flags = O_CREAT | O_WRONLY;
	fbr_ops_create(request, FBR_INODE_ROOT, testfile.name, S_IFREG, &fi);
	assert_zero(request->error);

	fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);
	fbr_ops_write(request, fio->file->inode, "bye.", 4, 6, &fi);
	assert_zero(request->error);

	fbr_ops_release(request, fio->file->inode, &fi);
	assert_zero(request->error);

	fbr_request_free(request);

	fbr_rlog(FBR_LOG_TEST, "*** Read testfile on fs_1");

	struct fbr_directory *root_fs1 = fbr_directory_load(fs_1, FBR_DIRNAME_ROOT,
		FBR_INODE_ROOT, 1);
	fbr_directory_ok(root_fs1);
	assert(root_fs1->state == FBR_DIRSTATE_OK);

	struct fbr_file *file_fs1 = fbr_directory_find_file(root_fs1, testfile.name,
		testfile.length);
	fbr_file_ok(file_fs1);
	assert(file_fs1->state == FBR_FILE_OK);
	assert(file_fs1->size == 10);

	char buffer[32];
	size_t buffer_len = fbr_test_fs_read(fs_1, file_fs1, 0, buffer, sizeof(buffer));
	assert(buffer_len == 10);
	buffer[buffer_len] = '\0';
	assert_zero(strcmp(buffer, "hello.bye."));

	fbr_dindex_release(fs_1, &root_fs1);

	fbr_rlog(FBR_LOG_TEST, "*** Cleanup");

	fbr_fs_release_all(fs_1, 1);
	fbr_test_fs_wait(fs_1);

	fbr_test_ERROR(fs_1->stats.directories, "non zero");
	fbr_test_ERROR(fs_1->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_1->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_1->stats.files, "non zero");
	fbr_test_ERROR(fs_1->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_1->stats.file_refs, "non zero");

	fbr_fs_free(fs_1);

	fbr_fs_release_all(fs_2, 1);
	fbr_test_fs_wait(fs_2);

	fbr_test_ERROR(fs_2->stats.directories, "non zero");
	fbr_test_ERROR(fs_2->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs_2->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs_2->stats.files, "non zero");
	fbr_test_ERROR(fs_2->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs_2->stats.file_refs, "non zero");

	fbr_fs_free(fs_2);

	fbr_test_logs("create_2fs_test done");
}
