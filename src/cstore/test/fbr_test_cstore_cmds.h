/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_FCACHE_CMDS_H_INCLUDED
#define _FBR_TEST_FCACHE_CMDS_H_INCLUDED

#include "cstore/fbr_cstore_api.h"
#include "test/fbr_test_cmd_declare.h"

struct fbr_test_cstore *fbr_test_tcstore_get(struct fbr_test_context *ctx, size_t index);
struct fbr_cstore *fbr_test_cstore_get(struct fbr_test_context *ctx, size_t index);

void fbr_test_cstore_register(void);
void fbr_test_cstore_unregister(void);
void fbr_test_cstore_init(struct fbr_test_context *ctx);
void fbr_test_cstore_init_loader(struct fbr_test_context *ctx);
void fbr_test_cstore_reload(struct fbr_test_context *ctx);
void fbr_test_cstore_wait(struct fbr_cstore *cstore);
void fbr_test_cstore_wait_0(void);
void fbr_test_cstore_debug(struct fbr_cstore *cstore);
void fbr_test_cstore_debug_0(void);
fbr_stats_t fbr_test_cstore_stat_chunks(void);
fbr_stats_t fbr_test_cstore_stat_indexes(void);
fbr_stats_t fbr_test_cstore_stat_roots(void);

#define FBR_CSTORE_MAX_CSTORES		6

struct fbr_test_cstore {
	unsigned int			magic;
#define FBR_TEST_CSTORE_MAGIC		0x57A22B5D

	struct fbr_cstore		cstore;

	char 				stat_buf[32];
	char				ip_str[128];
	char				port_str[16];

	struct fbr_test_cstore		*next;
};

#endif /* _FBR_TEST_FCACHE_CMDS_H_INCLUDED */

FBR_TEST_CMD(cstore_init)
FBR_TEST_CMD(cstore_test)
FBR_TEST_CMD(cstore_test_lru)
FBR_TEST_CMD(cstore_state_test)
FBR_TEST_CMD(cstore_wait_test)

FBR_TEST_CMD(cstore_async_test)
FBR_TEST_CMD(cstore_error_test)
FBR_TEST_CMD(cstore_loader_test)

FBR_TEST_CMD(cstore_debug)
FBR_TEST_VAR(cstore_stat_chunks)
FBR_TEST_VAR(cstore_stat_indexes)
FBR_TEST_VAR(cstore_stat_roots)
FBR_TEST_VAR(cstore_stat_chunk_write_bytes)
FBR_TEST_VAR(cstore_stat_chunk_read_bytes)

FBR_TEST_CMD(cstore_set_lru)
FBR_TEST_CMD(cstore_dirty_rm)
FBR_TEST_CMD(cstore_enable_server)
FBR_TEST_CMD(cstore_set_s3)

FBR_TEST_VAR(cstore_0_server_host)
FBR_TEST_VAR(cstore_0_server_port)
FBR_TEST_VAR(cstore_0_server_tls)
FBR_TEST_VAR(cstore_1_server_host)
FBR_TEST_VAR(cstore_1_server_port)
FBR_TEST_VAR(cstore_1_server_tls)
FBR_TEST_VAR(cstore_2_server_host)
FBR_TEST_VAR(cstore_2_server_port)
FBR_TEST_VAR(cstore_2_server_tls)
FBR_TEST_VAR(cstore_3_server_host)
FBR_TEST_VAR(cstore_3_server_port)
FBR_TEST_VAR(cstore_3_server_tls)
FBR_TEST_VAR(cstore_4_server_host)
FBR_TEST_VAR(cstore_4_server_port)
FBR_TEST_VAR(cstore_4_server_tls)
FBR_TEST_VAR(cstore_5_server_host)
FBR_TEST_VAR(cstore_5_server_port)
FBR_TEST_VAR(cstore_5_server_tls)
