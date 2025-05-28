/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef FBR_TEST_STORE_CMDS_H_INCLUDED
#define FBR_TEST_STORE_CMDS_H_INCLUDED

#ifndef FBR_TEST_STORE_CMD

#include "test/fbr_test.h"

#define FBR_TEST_STORE_CMD(cmd)	fbr_test_cmd_f fbr_cmd_##cmd;
#define FBR_TEST_STORE_VAR(var)	fbr_test_var_f fbr_var_##var;

void fbr_test_index_request_start(void);
void fbr_test_index_request_finish(void);

#endif /* FBR_TEST_STORE_CMD */

FBR_TEST_STORE_CMD(writer_test)
FBR_TEST_STORE_CMD(reader_test)

FBR_TEST_STORE_CMD(index_test)
FBR_TEST_STORE_CMD(index_large_test)
FBR_TEST_STORE_CMD(index_2fs_test)
FBR_TEST_STORE_CMD(index_2fs_thread_test)

FBR_TEST_STORE_CMD(store_write)
FBR_TEST_STORE_CMD(store_write_shared)
FBR_TEST_STORE_CMD(store_write_error)
FBR_TEST_STORE_CMD(store_write_error_flush)

FBR_TEST_STORE_CMD(dstore_debug)

#undef FBR_TEST_STORE_CMD
#undef FBR_TEST_STORE_VAR

#endif /* FBR_TEST_STORE_CMDS_H_INCLUDED */
