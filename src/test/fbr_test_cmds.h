/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FBR_TEST_CMDS_H_INCLUDED
#define FBR_TEST_CMDS_H_INCLUDED

#ifndef FBR_TEST_CMD

#include "test/fbr_test.h"

#define FBR_TEST_CMD(cmd)		fbr_test_cmd_f fbr_test_cmd_##cmd;
#define FBR_TEST_VAR(var)		fbr_test_var_f fbr_test_var_##var;

#endif /* FBR_TEST_CMD */

FBR_TEST_CMD(fiber_test)
FBR_TEST_CMD(skip)
FBR_TEST_CMD(sleep_ms)
FBR_TEST_CMD(equal)
FBR_TEST_CMD(not_equal)
FBR_TEST_CMD(print)

FBR_TEST_CMD(random_range)
FBR_TEST_VAR(random)

FBR_TEST_CMD(fs_mkdir_tmp)

#undef FBR_TEST_CMD
#undef FBR_TEST_VAR

#endif /* FBR_TEST_CMDS_H_INCLUDED */
