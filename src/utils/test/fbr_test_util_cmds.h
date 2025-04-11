/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_UTILS_CMDS_H_INCLUDED
#define FBR_TEST_UTILS_CMDS_H_INCLUDED

#ifndef FBR_TEST_UTILS_CMD

#include "test/fbr_test.h"

#define FBR_TEST_UTILS_CMD(cmd)	fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_UTILS_VAR(var)	fbr_test_var_f fbr_var_##var;

#endif /* FBR_TEST_UTILS_CMD */

FBR_TEST_UTILS_CMD(test_id_assert)

#undef FBR_TEST_UTILS_CMD
#undef FBR_TEST_UTILS_VAR

#endif /* FBR_TEST_UTILS_CMDS_H_INCLUDED */
