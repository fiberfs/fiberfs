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
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
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

	fbr_test_logs("*** Cleanup fs_1");

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
