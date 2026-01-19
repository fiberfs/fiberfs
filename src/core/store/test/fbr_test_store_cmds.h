/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_STORE_CMDS_H_INCLUDED
#define _FBR_TEST_STORE_CMDS_H_INCLUDED

#include "test/fbr_test_cmd_declare.h"

void fbr_test_index_request_start(void);
void fbr_test_index_request_finish(void);

#endif /* _FBR_TEST_STORE_CMDS_H_INCLUDED */

FBR_TEST_CMD(writer_test)
FBR_TEST_CMD(reader_test)

FBR_TEST_CMD(index_test)
FBR_TEST_CMD(index_large_test)
FBR_TEST_CMD(index_2fs_test)
FBR_TEST_CMD(index_2fs_thread_test)

FBR_TEST_CMD(store_write)
FBR_TEST_CMD(store_write_shared)
FBR_TEST_CMD(store_write_error)
FBR_TEST_CMD(store_write_error_flush)

FBR_TEST_CMD(merge_test)
FBR_TEST_CMD(merge_2fs_test)

FBR_TEST_CMD(append_2fs_test)
FBR_TEST_CMD(append_thread_test)
FBR_TEST_CMD(append_thread_error_test)
