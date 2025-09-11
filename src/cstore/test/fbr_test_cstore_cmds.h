/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_FCACHE_CMDS_H_INCLUDED
#define _FBR_TEST_FCACHE_CMDS_H_INCLUDED

#include "test/fbr_test_cmd_declare.h"

void fbr_test_cstore_init(struct fbr_test_context *ctx);
void fbr_test_cstore_debug(void);
fbr_stats_t fbr_test_cstore_stat_chunks(void);
fbr_stats_t fbr_test_cstore_stat_indexes(void);
fbr_stats_t fbr_test_cstore_stat_roots(void);

#endif /* _FBR_TEST_FCACHE_CMDS_H_INCLUDED */

FBR_TEST_CMD(cstore_init)
FBR_TEST_CMD(cstore_test)
FBR_TEST_CMD(cstore_test_lru)
FBR_TEST_CMD(cstore_state_test)

FBR_TEST_CMD(cstore_async_test)

FBR_TEST_CMD(cstore_debug)
FBR_TEST_VAR(cstore_stat_indexes)
FBR_TEST_VAR(cstore_stat_roots)
