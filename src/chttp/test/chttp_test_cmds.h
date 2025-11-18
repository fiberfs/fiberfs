/*
 * Copyright (c) 2024 chttp
 *
 */

#ifndef _CHTTP_TEST_CMDS_H_INCLUDED
#define _CHTTP_TEST_CMDS_H_INCLUDED

#include "chttp.h"
#include "test/fbr_test.h"

#define CHTTP_TEST_MD5_BUFLEN		33
#define CHTTP_TEST_GZIP_BUFLEN		4096

struct chttp_test_context {
	unsigned int			magic;
#define CHTTP_TEST_CONTEXT_MAGIC	0xD8B41328

	struct chttp_context		chttp_static;
	struct chttp_context		*chttp;

	struct chttp_test_server	*server;
	struct chttp_test_dns		*dns;
	struct chttp_test_tcp_pool	*tcp_pool;
	struct fbr_gzip			*gzip;
	char				gzip_buf[CHTTP_TEST_GZIP_BUFLEN];

	char				md5_server[CHTTP_TEST_MD5_BUFLEN];
	char				md5_client[CHTTP_TEST_MD5_BUFLEN];
};

void chttp_test_init(struct fbr_test_context *test);

struct fbr_md5_ctx;

void chttp_test_md5_store(struct fbr_md5_ctx *md5, char *buffer, size_t buffer_len);
void chttp_test_md5_store_server(struct fbr_test_context *ctx, struct fbr_md5_ctx *md5);
void chttp_test_md5_store_client(struct fbr_test_context *ctx, struct fbr_md5_ctx *md5);

#define chttp_test_context_ok(context)		\
	fbr_magic_check(context, CHTTP_TEST_CONTEXT_MAGIC)

#define CHTTP_TEST_CMD(cmd)		fbr_test_cmd_f chttp_test_cmd_##cmd;
#define CHTTP_TEST_VAR(var)		fbr_test_var_f chttp_test_var_##var;

#endif /* _CHTTP_TEST_CMDS_H_INCLUDED */

CHTTP_TEST_CMD(chttp_test)
CHTTP_TEST_CMD(connect_or_skip)
CHTTP_TEST_CMD(tls_or_skip)
CHTTP_TEST_CMD(gzip_or_skip)

CHTTP_TEST_CMD(chttp_init)
CHTTP_TEST_CMD(chttp_init_dynamic)
CHTTP_TEST_CMD(chttp_timeout_connect_ms)
CHTTP_TEST_CMD(chttp_timeout_transfer_ms)
CHTTP_TEST_CMD(chttp_version)
CHTTP_TEST_CMD(chttp_method)
CHTTP_TEST_CMD(chttp_url)
CHTTP_TEST_CMD(chttp_add_header)
CHTTP_TEST_CMD(chttp_delete_header)
CHTTP_TEST_CMD(chttp_connect)
CHTTP_TEST_CMD(chttp_new_connection)
CHTTP_TEST_CMD(chttp_enable_gzip)
CHTTP_TEST_CMD(chttp_send)
CHTTP_TEST_CMD(chttp_send_only)
CHTTP_TEST_CMD(chttp_send_body)
CHTTP_TEST_CMD(chttp_send_body_chunkgzip)
CHTTP_TEST_CMD(chttp_receive)
CHTTP_TEST_CMD(chttp_status_match)
CHTTP_TEST_CMD(chttp_reason_match)
CHTTP_TEST_CMD(chttp_header_match)
CHTTP_TEST_CMD(chttp_header_submatch)
CHTTP_TEST_CMD(chttp_header_exists)
CHTTP_TEST_CMD(chttp_version_match)
CHTTP_TEST_CMD(chttp_body_match)
CHTTP_TEST_CMD(chttp_body_submatch)
CHTTP_TEST_CMD(chttp_body_read)
CHTTP_TEST_CMD(chttp_body_md5)
CHTTP_TEST_CMD(chttp_s3_sign)
CHTTP_TEST_CMD(chttp_take_error)
CHTTP_TEST_CMD(chttp_reset)
CHTTP_TEST_VAR(chttp_reused)
CHTTP_TEST_VAR(chttp_is_gzip)
CHTTP_TEST_VAR(chttp_is_tls)

CHTTP_TEST_CMD(server_init)
CHTTP_TEST_CMD(server_accept)
CHTTP_TEST_CMD(server_close)
CHTTP_TEST_CMD(server_read_request)
CHTTP_TEST_CMD(server_method_match)
CHTTP_TEST_CMD(server_url_match)
CHTTP_TEST_CMD(server_url_submatch)
CHTTP_TEST_CMD(server_version_match)
CHTTP_TEST_CMD(server_header_match)
CHTTP_TEST_CMD(server_header_submatch)
CHTTP_TEST_CMD(server_header_exists)
CHTTP_TEST_CMD(server_header_not_exists)
CHTTP_TEST_CMD(server_body_match)
CHTTP_TEST_CMD(server_body_submatch)
CHTTP_TEST_CMD(server_body_read)
CHTTP_TEST_CMD(server_send_response)
CHTTP_TEST_CMD(server_send_response_H1_0)
CHTTP_TEST_CMD(server_send_response_partial)
CHTTP_TEST_CMD(server_send_header)
CHTTP_TEST_CMD(server_send_header_done)
CHTTP_TEST_CMD(server_enable_gzip)
CHTTP_TEST_CMD(server_start_chunked)
CHTTP_TEST_CMD(server_send_chunked)
CHTTP_TEST_CMD(server_send_chunked_gzip)
CHTTP_TEST_CMD(server_end_chunked)
CHTTP_TEST_CMD(server_send_raw)
CHTTP_TEST_CMD(server_send_raw_sock)
CHTTP_TEST_CMD(server_send_random_body)
CHTTP_TEST_CMD(server_sleep_ms)
CHTTP_TEST_CMD(server_flush_async)
CHTTP_TEST_VAR(server_host)
CHTTP_TEST_VAR(server_port)
CHTTP_TEST_VAR(server_tls)

CHTTP_TEST_VAR(md5_server)
CHTTP_TEST_VAR(md5_client)

CHTTP_TEST_CMD(dns_ttl)
CHTTP_TEST_CMD(dns_cache_size)
CHTTP_TEST_CMD(dns_lookup)
CHTTP_TEST_CMD(dns_lookup_or_skip)
CHTTP_TEST_CMD(dns_debug)
CHTTP_TEST_VAR(dns_value)
CHTTP_TEST_VAR(dns_lookups)
CHTTP_TEST_VAR(dns_cache_hits)
CHTTP_TEST_VAR(dns_insertions)
CHTTP_TEST_VAR(dns_dups)
CHTTP_TEST_VAR(dns_expired)
CHTTP_TEST_VAR(dns_nuked)
CHTTP_TEST_VAR(dns_lru)
CHTTP_TEST_VAR(dns_err_too_long)
CHTTP_TEST_VAR(dns_err_alloc)

CHTTP_TEST_CMD(tcp_pool_debug)
CHTTP_TEST_CMD(tcp_pool_age_ms)
CHTTP_TEST_CMD(tcp_pool_size)
CHTTP_TEST_CMD(tcp_pool_fake_connect)
CHTTP_TEST_VAR(tcp_pool_lookups)
CHTTP_TEST_VAR(tcp_pool_cache_hits)
CHTTP_TEST_VAR(tcp_pool_cache_misses)
CHTTP_TEST_VAR(tcp_pool_insertions)
CHTTP_TEST_VAR(tcp_pool_expired)
CHTTP_TEST_VAR(tcp_pool_deleted)
CHTTP_TEST_VAR(tcp_pool_nuked)
CHTTP_TEST_VAR(tcp_pool_lru)
CHTTP_TEST_VAR(tcp_pool_err_alloc)
