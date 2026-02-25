/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_CONFIG_CMDS_H_INCLUDED
#define _FBR_TEST_CONFIG_CMDS_H_INCLUDED

#include "test/fbr_test_cmd_declare.h"

void fbr_test_conf_add(const char *name, const char *value);
void fbr_test_conf_add_long(const char *name, long value);

#endif /* _FBR_TEST_CONFIG_CMDS_H_INCLUDED */

FBR_TEST_CMD(config_add)
FBR_TEST_CMD(config_file)
FBR_TEST_VARF(config)

FBR_TEST_CMD(test_config_simple)
FBR_TEST_CMD(test_config_static)
FBR_TEST_CMD(test_config_file)
FBR_TEST_CMD(test_config_file_errors)
FBR_TEST_CMD(test_config_thread)
FBR_TEST_CMD(test_config_reader)
