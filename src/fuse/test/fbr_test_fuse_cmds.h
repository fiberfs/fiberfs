/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FBR_TEST_FUSE_CMDS_H_INCLUDED
#define FBR_TEST_FUSE_CMDS_H_INCLUDED

#ifndef FBR_TEST_FUSE_CMD

#include "test/fbr_test.h"

#define FBR_TEST_FUSE_CMD(cmd)		fbr_test_cmd_f fbr_test_fuse_cmd_##cmd;
#define FBR_TEST_FUSE_VAR(var)		fbr_test_var_f fbr_test_fuse_var_##var;

#endif /* FBR_TEST_FUSE_CMD */

#ifndef FBR_TEST_FUSE_CMD
#error "FBR_TEST_FUSE_CMD missing"
#endif
#ifndef FBR_TEST_FUSE_VAR
#error "FBR_TEST_FUSE_VAR missing"
#endif

FBR_TEST_FUSE_CMD(fuse_test)

#undef FBR_TEST_FUSE_CMD
#undef FBR_TEST_FUSE_VAR

#endif /* FBR_TEST_FUSE_CMDS_H_INCLUDED */
