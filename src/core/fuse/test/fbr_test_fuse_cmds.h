/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_FUSE_CMDS_H_INCLUDED
#define _FBR_TEST_FUSE_CMDS_H_INCLUDED

#include "test/fbr_test.h"
#include "test/fbr_test_cmd_declare.h"
#include "core/fuse/fbr_fuse.h"
#include "core/request/fbr_request.h"

struct fbr_test_fuse {
	unsigned int			magic;
#define FBR_TEST_FUSE_MAGIC		0x323EF113

	struct fbr_fuse_context		fuse_ctx;

	char				stat_str[64];
};

int fbr_fuse_test_mount(struct fbr_test_context *test_ctx, const char *path,
	const struct fbr_fuse_callbacks *fuse_callbacks);
void fbr_fuse_test_unmount(struct fbr_test_context *test_ctx);
struct fbr_fuse_context *fbr_test_fuse_get_ctx(struct fbr_test_context *test_ctx);
void fbr_test_fuse_mock(struct fbr_test_context *test_ctx);
struct fbr_fs *fbr_test_fuse_mock_fs(struct fbr_test_context *test_ctx);
void fbr_test_fuse_root_alloc(struct fbr_fs *fs);

#endif /* _FBR_TEST_FUSE_CMDS_H_INCLUDED */

FBR_TEST_CMD(fuse_test_mount)
FBR_TEST_CMD(fuse_test_unmount)

FBR_TEST_CMD(fuse_test_ops_mount)
FBR_TEST_CMD(fuse_test_ops_unmount)

FBR_TEST_CMD(fuse_error_mount)
