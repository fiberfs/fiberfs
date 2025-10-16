/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_REQUEST_CMDS_H_INCLUDED
#define _FBR_TEST_REQUEST_CMDS_H_INCLUDED

#include "test/fbr_test_cmd_declare.h"

struct fbr_request *fbr__test_request_mock(const char *function);

#define fbr_test_request_mock()		\
	fbr__test_request_mock(__func__)

#endif /* _FBR_TEST_REQUEST_CMDS_H_INCLUDED */

FBR_TEST_CMD(workspace_test_asserts)
FBR_TEST_CMD(workspace_test)

FBR_TEST_CMD(request_test)
FBR_TEST_CMD(request_test_thread)
FBR_TEST_CMD(request_test_active)
