/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_FCACHE_CMDS_H_INCLUDED
#define FBR_TEST_FCACHE_CMDS_H_INCLUDED

#ifndef FBR_TEST_FCACHE_CMD

#include "test/fbr_test.h"

#define FBR_TEST_FCACHE_CMD(cmd)	fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_FCACHE_VAR(var)	fbr_test_var_f fbr_var_##var;

#endif /* FBR_TEST_FCACHE_CMD */

FBR_TEST_FCACHE_CMD(cstore_init)

#undef FBR_TEST_FCACHE_CMD
#undef FBR_TEST_FCACHE_VAR

#endif /* FBR_TEST_FCACHE_CMDS_H_INCLUDED */
