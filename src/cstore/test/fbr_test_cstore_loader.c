/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "fbr_test_cstore_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

extern struct fbr_cstore *_CSTORE;

void
fbr_cmd_cstore_loader_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** Allocating fs and root");

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_init(ctx);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_logs("*** Cleanup");

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_loader_test done");
}
