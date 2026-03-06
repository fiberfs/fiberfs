/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_CONFIG_CMDS_H_INCLUDED
#define _FBR_TEST_CONFIG_CMDS_H_INCLUDED

#include "config/fbr_config.h"
#include "test/fbr_test_cmd_declare.h"

#define fbr_test_conf_add(name, value)			\
	fbr_test_config_add(_CONFIG, name, value)
#define fbr_test_conf_add_long(name, value)		\
	fbr_test_config_add_long(_CONFIG, name, value)

void fbr_test_config_add(struct fbr_config *config, const char *name, const char *value);
void fbr_test_config_add_long(struct fbr_config *config, const char *name, long value);

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
