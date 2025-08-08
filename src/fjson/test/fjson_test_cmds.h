/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FJSON_TEST_CMDS_H_INCLUDED
#define _FJSON_TEST_CMDS_H_INCLUDED

#include "fjson.h"
#include "test/fbr_test.h"

#define FJSON_TEST_CMD(cmd)		fbr_test_cmd_f fjson_cmd_##cmd;
#define FJSON_TEST_VAR(var)		fbr_test_var_f fjson_var_##var;

#endif /* _FJSON_TEST_CMDS_H_INCLUDED */

FJSON_TEST_CMD(json_test)
FJSON_TEST_CMD(json_dynamic)
FJSON_TEST_CMD(json_fail)
FJSON_TEST_CMD(json_multi)
FJSON_TEST_CMD(json_file)
FJSON_TEST_CMD(json_file_fail)
