/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_OPS_CMDS_H_INCLUDED
#define FBR_TEST_OPS_CMDS_H_INCLUDED

#ifndef FBR_TEST_OPS_CMD

#include "test/fbr_test.h"

#define FBR_TEST_OPS_CMD(cmd)	fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_OPS_VAR(var)	fbr_test_var_f fbr_var_##var;

#endif /* FBR_TEST_OPS_CMD */

FBR_TEST_OPS_CMD(mkdir_op_test_mount)
FBR_TEST_OPS_CMD(mkdir_test_fail)

#undef FBR_TEST_OPS_CMD
#undef FBR_TEST_OPS_VAR

#endif /* FBR_TEST_OPS_CMDS_H_INCLUDED */
