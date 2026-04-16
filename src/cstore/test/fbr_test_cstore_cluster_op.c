/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

void
fbr_cmd_cstore_cluster_ops(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_cstore *cstore_c0_shared = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(cstore_c0_shared);

	struct fbr_cstore *cstore_c1_s3 = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(cstore_c1_s3);

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);
	fbr_test_cstore_bind_new(fs);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_fuse_root_alloc(fs);

	fbr_fs_free(fs);

	fbr_test_logs("cstore_cluster_ops done");
}
