/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FBR_TEST_COREFS_CMDS_H_INCLUDED
#define FBR_TEST_COREFS_CMDS_H_INCLUDED

#ifndef FBR_TEST_FS_CMD

#include "test/fbr_test.h"

#define FBR_TEST_FS_CMD(cmd)		fbr_test_cmd_f fbr_test_cmd_##cmd;
#define FBR_TEST_FS_VAR(var)		fbr_test_var_f fbr_test_var_##var;

#endif /* FBR_TEST_FS_CMD */

FBR_TEST_FS_CMD(fs_test_simple_mount)

#undef FBR_TEST_FS_CMD
#undef FBR_TEST_FS_VAR

#endif /* FBR_TEST_COREFS_CMDS_H_INCLUDED */
