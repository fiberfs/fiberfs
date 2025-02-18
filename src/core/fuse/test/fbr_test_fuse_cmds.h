/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_FUSE_CMDS_H_INCLUDED
#define FBR_TEST_FUSE_CMDS_H_INCLUDED

#ifndef FBR_TEST_FUSE_CMD

#include "test/fbr_test.h"
#include "core/fuse/fbr_fuse.h"
#include "core/context/fbr_callback.h"

#define FBR_TEST_FUSE_CMD(cmd)		fbr_test_cmd_f fbr_test_fuse_cmd_##cmd;
#define FBR_TEST_FUSE_VAR(var)		fbr_test_var_f fbr_test_fuse_var_##var;

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
struct fbr_test_context *fbr_test_fuse_ctx(void);

#endif /* FBR_TEST_FUSE_CMD */

FBR_TEST_FUSE_CMD(fuse_test_mount)
FBR_TEST_FUSE_CMD(fuse_test_unmount)

FBR_TEST_FUSE_CMD(fuse_test_ops_mount)
FBR_TEST_FUSE_CMD(fuse_test_ops_unmount)

#undef FBR_TEST_FUSE_CMD
#undef FBR_TEST_FUSE_VAR

#endif /* FBR_TEST_FUSE_CMDS_H_INCLUDED */
