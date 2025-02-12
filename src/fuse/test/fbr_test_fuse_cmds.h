/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FBR_TEST_FUSE_CMDS_H_INCLUDED
#define FBR_TEST_FUSE_CMDS_H_INCLUDED

#ifndef FBR_TEST_FUSE_CMD

#include "test/fbr_test.h"
#include "fuse/fbr_fuse.h"

#define FBR_TEST_FUSE_CMD(cmd)		fbr_test_cmd_f fbr_test_fuse_cmd_##cmd;
#define FBR_TEST_FUSE_VAR(var)		fbr_test_var_f fbr_test_fuse_var_##var;

struct fbr_test_fuse {
	unsigned int			magic;
#define _FUSE_MAGIC			0x323EF113

	struct fbr_fuse_context		ctx;

	char				stat_str[64];
};

struct fuse_lowlevel_ops;

int fbr_fuse_test_mount(struct fbr_test_context *test_ctx, const char *path,
	const struct fuse_lowlevel_ops *fuse_ops);
void fbr_fuse_test_unmount(struct fbr_test_context *test_ctx);
struct fbr_fuse_context *fbr_test_fuse_get_ctx(struct fbr_test_context *test_ctx);
void __fbr_attr_printf(4) fbr_test_fuse_ERROR(int condition, struct fbr_fuse_context *ctx,
	void *req, const char *fmt, ...);

#define fbr_test_fuse_ASSERT(cond, ctx, req, fmt, ...)				\
	fbr_test_fuse_ERROR(!(cond), ctx, req, fmt, ##__VA_ARGS__);

#endif /* FBR_TEST_FUSE_CMD */

FBR_TEST_FUSE_CMD(fuse_test_mount)
FBR_TEST_FUSE_CMD(fuse_test_unmount)

FBR_TEST_FUSE_CMD(fuse_test_ops_mount)
FBR_TEST_FUSE_CMD(fuse_test_ops_unmount)

#undef FBR_TEST_FUSE_CMD
#undef FBR_TEST_FUSE_VAR

#endif /* FBR_TEST_FUSE_CMDS_H_INCLUDED */
