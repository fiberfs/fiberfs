/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FJSON_TEST_CMDS_H_INCLUDED
#define FJSON_TEST_CMDS_H_INCLUDED

#ifndef FJSON_TEST_CMD

#include "fjson.h"
#include "test/fbr_test.h"

#define FJSON_TEST_CMD(cmd)		fbr_test_cmd_f fjson_cmd_##cmd;
#define FJSON_TEST_VAR(var)		fbr_test_var_f fjson_var_##var;

#endif /* FJSON_TEST_CMD */

#ifndef FJSON_TEST_CMD
#error "FJSON_TEST_CMD missing"
#endif
#ifndef FJSON_TEST_VAR
#error "FJSON_TEST_VAR missing"
#endif

FJSON_TEST_CMD(json_test)
FJSON_TEST_CMD(json_dynamic)
FJSON_TEST_CMD(json_fail)
FJSON_TEST_CMD(json_multi)
FJSON_TEST_CMD(json_file)
FJSON_TEST_CMD(json_file_fail)

#undef FJSON_TEST_CMD
#undef FJSON_TEST_VAR

#endif /* FJSON_TEST_CMDS_H_INCLUDED */
