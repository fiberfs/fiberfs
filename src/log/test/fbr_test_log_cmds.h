/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_LOG_CMDS_H_INCLUDED
#define _FBR_TEST_LOG_CMDS_H_INCLUDED

#include "test/fbr_test.h"
#include "test/fbr_test_cmd_declare.h"

void fbr_test_log_printer_init(struct fbr_test_context *ctx, const char *logname,
	const char *prefix);
void fbr_test_log_printer_silent(int silent);
size_t fbr_test_log_printer_lines(void);

#endif /* _FBR_TEST_LOG_CMDS_H_INCLUDED */

FBR_TEST_CMD(test_log_size)
FBR_TEST_CMD(test_log_assert)
FBR_TEST_CMD(test_log_debug)
FBR_TEST_CMD(test_log_init)
FBR_TEST_CMD(test_log_loop)
FBR_TEST_CMD(test_log_rlog)
FBR_TEST_CMD(test_log_printer)
