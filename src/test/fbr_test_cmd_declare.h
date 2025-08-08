/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_CMD_DECLARE_H_INCLUDED
#define _FBR_TEST_CMD_DECLARE_H_INCLUDED

#include "fbr_test.h"

#define FBR_TEST_CMD(cmd)	fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_VAR(var)	fbr_test_var_f fbr_var_##var;

#endif /* _FBR_TEST_CMD_DECLARE_H_INCLUDED */
