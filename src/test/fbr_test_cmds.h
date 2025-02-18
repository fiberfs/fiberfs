/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
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
FBR_TEST_CMD(set_timeout_sec)

FBR_TEST_CMD(random_range)
FBR_TEST_VAR(random)

FBR_TEST_CMD(fs_mkdir_tmp)
FBR_TEST_VAR(fs_tmpdir)
FBR_TEST_CMD(fs_ls)
FBR_TEST_CMD(fs_cat)

FBR_TEST_CMD(set_var1)
FBR_TEST_CMD(set_var2)
FBR_TEST_CMD(set_var3)
FBR_TEST_CMD(set_var4)
FBR_TEST_CMD(set_var5)
FBR_TEST_VAR(var1)
FBR_TEST_VAR(var2)
FBR_TEST_VAR(var3)
FBR_TEST_VAR(var4)
FBR_TEST_VAR(var5)

#undef FBR_TEST_CMD
#undef FBR_TEST_VAR

#endif /* FBR_TEST_CMDS_H_INCLUDED */
