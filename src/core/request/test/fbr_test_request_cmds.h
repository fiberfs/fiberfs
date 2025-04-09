/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_REQUEST_CMDS_H_INCLUDED
#define FBR_TEST_REQUEST_CMDS_H_INCLUDED

#ifndef FBR_TEST_REQUEST_CMD

#include "test/fbr_test.h"

#define FBR_TEST_REQUEST_CMD(cmd)	fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_REQUEST_VAR(var)	fbr_test_var_f fbr_var_##var;

#endif /* FBR_TEST_REQUEST_CMD */

FBR_TEST_REQUEST_CMD(workspace_test_asserts)
FBR_TEST_REQUEST_CMD(workspace_test)

FBR_TEST_REQUEST_CMD(request_test)

#undef FBR_TEST_REQUEST_CMD
#undef FBR_TEST_REQUEST_VAR

#endif /* FBR_TEST_REQUEST_CMDS_H_INCLUDED */
