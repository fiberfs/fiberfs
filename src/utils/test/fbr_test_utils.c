/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/fuse/fbr_fuse_lowlevel.h"
#include "test/fbr_test.h"

void
fbr_cmd_test_utils(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	assert(fbr_ulong2octal(22) == 0022);
	assert(fbr_ulong2octal(644) == 0644);
	assert(fbr_ulong2octal(755) == 0755);
	assert(fbr_ulong2octal(0) == 0000);

	fbr_test_logs("** octals passed");

	struct fbr_file _file;
	struct fbr_file *file = &_file;
	fbr_zero(file);
	file->magic = FBR_FILE_MAGIC;
	fbr_file_ok(file);

	struct fuse_ctx fctx;
	fbr_zero(&fctx);

	fctx.uid = 2000;
	fctx.gid = 200;
	file->uid = 2000;
	file->gid = 200;
	file->mode = fbr_ulong2octal(640);

	assert(fbr_fuse_check_access(&fctx, file, R_OK));
	assert(fbr_fuse_check_access(&fctx, file, W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, X_OK));
	assert(fbr_fuse_check_access(&fctx, file, R_OK | W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK | X_OK));

	fctx.uid = 1000;

	assert(fbr_fuse_check_access(&fctx, file, R_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, X_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK | X_OK));

	fctx.gid = 100;

	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, X_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK | X_OK));

	fctx.uid = 2000;
	fctx.gid = 200;
	file->uid = 2000;
	file->gid = 200;
	file->mode = fbr_ulong2octal(751);

	assert(fbr_fuse_check_access(&fctx, file, R_OK));
	assert(fbr_fuse_check_access(&fctx, file, W_OK));
	assert(fbr_fuse_check_access(&fctx, file, X_OK));
	assert(fbr_fuse_check_access(&fctx, file, W_OK | X_OK));

	fctx.uid = 1000;

	assert(fbr_fuse_check_access(&fctx, file, R_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK));
	assert(fbr_fuse_check_access(&fctx, file, X_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK | X_OK));

	fctx.gid = 100;

	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK));
	assert(fbr_fuse_check_access(&fctx, file, X_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK | X_OK));

	fctx.uid = 2000;
	fctx.gid = 200;
	file->uid = 2000;
	file->gid = 200;
	file->mode = fbr_ulong2octal(0);

	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, X_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK));
	assert_zero(fbr_fuse_check_access(&fctx, file, R_OK | W_OK | X_OK));

	fctx.uid = 0;
	fctx.gid = 0;
	file->uid = 2000;
	file->gid = 200;
	file->mode = fbr_ulong2octal(0);

	assert(fbr_fuse_check_access(&fctx, file, R_OK));
	assert(fbr_fuse_check_access(&fctx, file, W_OK));
	assert(fbr_fuse_check_access(&fctx, file, X_OK));
	assert(fbr_fuse_check_access(&fctx, file, R_OK | W_OK));
	assert(fbr_fuse_check_access(&fctx, file, R_OK | W_OK | X_OK));

	fbr_test_logs("** access passed");

	fbr_test_logs("test_utils passed");
}
