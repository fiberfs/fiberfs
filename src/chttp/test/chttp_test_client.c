/*
 * Copyright (c) 2021 chttp
 *
 */

#include <stdlib.h>
#include <sys/socket.h>

#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"
#include "compress/chttp_gzip.h"
#include "cstore/fbr_cstore_api.h"
#include "cstore/test/fbr_test_cstore_cmds.h"
#include "network/chttp_tcp_pool.h"
#include "tls/chttp_tls.h"
#include "utils/fbr_chash.h"

static const char *_TEST_REASON = "_REASON";

static inline struct chttp_context *
_test_context_ok(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	fbr_test_ERROR(!ctx->chttp_test->chttp, "chttp context does not exist");
	chttp_context_ok(ctx->chttp_test->chttp);
	fbr_test_ok(fbr_test_convert(ctx));

	return ctx->chttp_test->chttp;
}

static void
_test_client_finish(struct fbr_test_context *ctx)
{
	struct chttp_context *chttp = _test_context_ok(ctx);

	if (chttp->state < CHTTP_STATE_IDLE && chttp->addr.state == CHTTP_ADDR_CONNECTED) {
		fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "chttp addr is hung");
		shutdown(chttp->addr.sock, SHUT_RDWR);
		fbr_test_sleep_ms(25);
	}

	fbr_finish_ERROR(chttp->error, "chttp context has an error");

	size_t allocs = 0;

	if (chttp->do_free) {
		allocs++;
	}

	struct chttp_dpage *dpage = chttp->dpage;
	while(dpage) {
		if (dpage->free) {
			allocs++;
		}
		dpage = dpage->next;
	}

	chttp_context_free(chttp);
	ctx->chttp_test->chttp = NULL;
	chttp = NULL;

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "context contained %zu allocations", allocs);

	chttp_tcp_pool_close();

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "tcp pool cleanup");

	chttp_tls_free();

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "TLS shutdown");
}

void
chttp_test_cmd_chttp_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	fbr_test_ERROR_param_count(cmd, 0);
	fbr_test_ERROR(ctx->chttp_test->chttp != NULL, "chttp context exists");

	ctx->chttp_test->chttp = &ctx->chttp_test->chttp_static;

	chttp_context_init(ctx->chttp_test->chttp);
	chttp_context_ok(ctx->chttp_test->chttp);

	fbr_test_register_finish(ctx, "chttp_client", _test_client_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_init_dynamic(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);

	fbr_test_ERROR(cmd->param_count > 1, "too many parameters");
	fbr_test_ERROR(ctx->chttp_test->chttp != NULL, "chttp context exists");

	long size = 0;

	if (cmd->param_count == 1) {
		size = fbr_test_parse_long(cmd->params[0].value);
		fbr_test_ERROR(size <= 0, "chttp size must be greater than 0");
	}

	_DEBUG_CHTTP_DPAGE_MIN_SIZE = (size_t)size;

	ctx->chttp_test->chttp = chttp_context_alloc();
	chttp_context_ok(ctx->chttp_test->chttp);

	fbr_test_register_finish(ctx, "chttp_client", _test_client_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_timeout_connect_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	chttp_addr_ok(&chttp->addr);
	fbr_test_ERROR_param_count(cmd, 1);

	int timeout = (int)fbr_test_parse_long(cmd->params[0].value);

	fbr_test_ERROR(chttp->addr.state != CHTTP_ADDR_RESOLVED,
		"Address must be resolved first");

	chttp->addr.timeout_connect_ms = timeout;
}

void
chttp_test_cmd_chttp_timeout_transfer_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	chttp_addr_ok(&chttp->addr);
	fbr_test_ERROR_param_count(cmd, 1);

	int timeout = (int)fbr_test_parse_long(cmd->params[0].value);

	fbr_test_ERROR(chttp->addr.state != CHTTP_ADDR_RESOLVED, "Address must be resolved first");

	chttp->addr.timeout_transfer_ms = timeout;
}

void
chttp_test_cmd_chttp_version(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long version = fbr_test_parse_long(cmd->params[0].value);

	switch (version) {
		case 10:
			chttp_set_version(chttp, CHTTP_H_VERSION_1_0);
			return;
		case 11:
			chttp_set_version(chttp, CHTTP_H_VERSION_1_1);
			return;
	}

	fbr_test_ERROR(1, "unsupported chttp version %ld", version);
}

void
chttp_test_cmd_chttp_method(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_set_method(chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_url(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_set_url(chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_add_header(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	fbr_test_unescape(&cmd->params[1]);

	chttp_header_add(chttp, cmd->params[0].value, cmd->params[1].value);
}

void
chttp_test_cmd_chttp_delete_header(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_header_delete(chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_connect(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 3, "too many parameters");
	fbr_test_ERROR(cmd->param_count < 2, "missing parameters");
	fbr_test_ERROR_string(cmd->params[0].value);
	fbr_test_ERROR_string(cmd->params[1].value);

	int tls = 0;

	if (cmd->param_count >= 3) {
		fbr_test_ERROR_string(cmd->params[2].value);
		if (!strcmp(cmd->params[2].value, "1")) {
			tls = 1;
		}
	}

	long port = fbr_test_parse_long(cmd->params[1].value);
	fbr_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	chttp_connect(chttp, cmd->params[0].value, cmd->params[0].len, port, tls);

	fbr_test_ERROR(chttp->error, "connection failed: %s", chttp_error_msg(chttp));

	char name[256];
	int outport;
	chttp_sa_string(&chttp->addr.sa, name, sizeof(name), &outport);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "lookup made to %s:%ld => %s:%d",
		cmd->params[0].value, port, name, outport);

	if (fbr_test_is_valgrind()) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "valgrind detected, bumping timeouts");
		chttp->addr.timeout_connect_ms = 60000;
		chttp->addr.timeout_transfer_ms = 120000;
	}
}

char *
chttp_test_var_chttp_reused(struct fbr_test_context *ctx)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	chttp_addr_ok(&chttp->addr);

	if (chttp->addr.reused) {
		return "1";
	} else {
		return "0";
	}
}

void
chttp_test_cmd_chttp_new_connection(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp->new_conn = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "new connection set");
}

void
chttp_test_cmd_chttp_enable_gzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp->gzip = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "gzip enabled");
}

void
chttp_test_cmd_chttp_send_only(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_send(chttp);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request sent");
}

void
chttp_test_cmd_chttp_send_body(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_body_send(chttp, cmd->params[0].value, cmd->params[0].len);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request body sent");
}

void
chttp_test_cmd_chttp_send_body_chunkgzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	assert(chttp->state == CHTTP_STATE_SENT);
	chttp_addr_connected(&chttp->addr);

	struct fbr_gzip gzip;
	char buf[1024];
	fbr_gzip_deflate_init(&gzip);
	chttp_gzip_register(NULL, &gzip, buf, sizeof(buf));

	chttp_gzip_send_chunk(&gzip, &chttp->addr, cmd->params[0].value,
		cmd->params[0].len);
	chttp_gzip_send_chunk(&gzip, &chttp->addr, NULL, 0);
	chttp_tcp_send(&chttp->addr, "0\r\n\r\n", 5);

	fbr_gzip_free(&gzip);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request body sent chunked gzip");
}

void
chttp_test_cmd_chttp_receive(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	struct fbr_test *test = fbr_test_convert(ctx);

	chttp_receive(chttp);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request received");

	if (test->verbocity == FBR_LOG_VERY_VERBOSE) {
		printf("--- ");
		chttp_context_debug(chttp);
	}

	assert_zero(chttp->request);
}

void
chttp_test_cmd_chttp_send(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_test_cmd_chttp_send_only(ctx, cmd);
	fbr_test_ERROR(chttp->error, "chttp send error");

	chttp_test_cmd_chttp_receive(ctx, cmd);
}

void
chttp_test_cmd_chttp_status_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long status = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(status <= 0 || status > 999, "invalid status");

	fbr_test_ERROR(chttp->status != status,
		"invalid status (wanted %ld, found %d)", status, chttp->status);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "status OK (%ld)", status);
}

static void
_test_header_match(struct fbr_test_context *ctx, const char *header, const char *expected,
    int sub)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	assert(header);

	const char *header_value;

	if (header == _TEST_REASON) {
		header_value = chttp_header_get_reason(chttp);
	} else {
		header_value = chttp_header_get(chttp, header);
	}

	fbr_test_ERROR(!header_value, "header %s not found", header);

	const char *dup = chttp_header_get_pos(chttp, header, 1);
	fbr_test_warn(dup != NULL, "duplicate %s header found", header);

	if (!expected) {
		fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "header exists %s", header);
		return;
	}

	if (sub) {
		fbr_test_ERROR(!strstr(header_value, expected), "value %s not found in header "
			"%s:%s", expected, header, header_value);
	} else {
		fbr_test_ERROR(strcmp(header_value, expected), "headers dont match, found %s:%s, "
			"expected %s", header, header_value, expected);
	}

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "headers match %s:%s%s%s%s",
		header, header_value, sub ? " (" : "", sub ? expected : "", sub ? ")" : "");
}

void
chttp_test_cmd_chttp_reason_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	_test_header_match(ctx, _TEST_REASON, cmd->params[0].value, 0);
}

void
chttp_test_cmd_chttp_header_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	fbr_test_unescape(&cmd->params[1]);

	_test_header_match(ctx, cmd->params[0].value, cmd->params[1].value, 0);
}

void
chttp_test_cmd_chttp_header_submatch(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	fbr_test_unescape(&cmd->params[1]);

	_test_header_match(ctx, cmd->params[0].value, cmd->params[1].value, 1);
}

void
chttp_test_cmd_chttp_header_exists(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	_test_header_match(ctx, cmd->params[0].value, NULL, 1);
}

void
chttp_test_cmd_chttp_version_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long version = fbr_test_parse_long(cmd->params[0].value);
	enum chttp_version expected = 0;

	switch (version) {
		case 10:
			expected = CHTTP_H_VERSION_1_0;
			break;
		case 11:
			expected = CHTTP_H_VERSION_1_1;
			break;
		default:
			fbr_test_ERROR(1, "unsupported chttp version %ld", version);
	}

	fbr_test_ERROR(expected != chttp->version, "version mismatch, expected %d, found %d",
		expected, chttp->version);
}

static void
_test_body_match(struct fbr_test_context *ctx, const char *expected, int sub, size_t size)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR(chttp->state != CHTTP_STATE_BODY, "chttp no body found");

	char gzip_buf[4096];
	struct fbr_gzip *gzip;
	char *body = NULL;
	size_t read;
	size_t body_len = 0;
	size_t calls = 0;

	if (size == 0) {
		size = 1024;
	}

	if (chttp->gzip && fbr_gzip_enabled()) {
		gzip = fbr_gzip_inflate_alloc();
		chttp_gzip_register(chttp, gzip, gzip_buf, sizeof(gzip_buf));
	}

	do {
		if (calls) {
			size_t old_size = size;
			size *= 2;
			assert(size / 2 == old_size);
		}

		body = realloc(body, size + 1);
		assert(body);

		read = chttp_body_read(chttp, body + body_len, size - body_len);

		// TODO test
		if (chttp->state == CHTTP_STATE_BODY) {
			assert(read > 0);
		}

		body_len += read;
		calls++;
	} while (read);

	assert(chttp->state > CHTTP_STATE_BODY);

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "read %zu body bytes in %zu call(s)",
		body_len, calls);

	if (!expected) {
		free(body);
		return;
	}

	fbr_test_ERROR(chttp->error, "chttp error %s", chttp_error_msg(chttp));

	body[body_len] = '\0';

	if (sub) {
		fbr_test_ERROR(!strstr(body, expected), "value %s not found in body", expected);
	} else if (!sub) {
		fbr_test_ERROR(strcmp(body, expected), "bodies dont match");
	}

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "bodies match");

	free(body);
}

void
chttp_test_cmd_chttp_body_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 2, "too many parameters");
	fbr_test_ERROR(cmd->param_count < 1, "missing parameters");

	long size = 0;

	if (cmd->param_count == 2) {
		size = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ERROR(size < 0, "invalid size");
	}

	_test_body_match(ctx, cmd->params[0].value, 0, size);
}

void
chttp_test_cmd_chttp_body_submatch(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 2, "too many parameters");
	fbr_test_ERROR(cmd->param_count < 1, "missing parameters");

	long size = 0;

	if (cmd->param_count == 2) {
		size = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ERROR(size < 0, "invalid size");
	}

	_test_body_match(ctx, cmd->params[0].value, 1, size);
}

void
chttp_test_cmd_chttp_body_read(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_body_match(ctx, NULL, 0, 0);
}

void
chttp_test_cmd_chttp_body_md5(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp;

	chttp = _test_context_ok(ctx);
	fbr_test_ERROR(chttp->state != CHTTP_STATE_BODY, "chttp no body found");
	fbr_test_ERROR_param_count(cmd, 0);

	uint8_t buf[8192];
	size_t len;
	struct fbr_gzip *gzip;
	char gzip_buf[4096];

	struct fbr_md5_ctx md5;
	fbr_md5_init(&md5);

	size_t body_len = 0;
	size_t calls = 0;

	if (chttp->gzip && fbr_gzip_enabled()) {
		gzip = fbr_gzip_inflate_alloc();
		chttp_gzip_register(chttp, gzip, gzip_buf, sizeof(gzip_buf));
	}

	do {
		len = chttp_body_read(chttp, buf, sizeof(buf));

		fbr_md5_update(&md5, buf, len);

		body_len += len;
		calls++;
	} while (len > 0);

	assert(chttp->state > CHTTP_STATE_BODY);
	fbr_test_ERROR(chttp->error, "chttp error %s", chttp_error_msg(chttp));

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "read %zu body bytes in %zu call(s)",
		body_len, calls);

	fbr_md5_final(&md5);
	chttp_test_md5_store_client(ctx, &md5);

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "body md5 %s", ctx->chttp_test->md5_client);
}

void
chttp_test_cmd_chttp_s3_sign(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count >= 4 && cmd->param_count <= 5);

	const char *host = cmd->params[0].value;
	const char *region = cmd->params[1].value;
	const char *access_key = cmd->params[2].value;
	const char *secret_key = cmd->params[3].value;

	time_t sign_time = 0;
	if (cmd->param_count >= 5) {
		sign_time = fbr_test_parse_long(cmd->params[4].value);
	}

	fbr_cstore_s3_sign(chttp, sign_time, 0, fbr_cstore_s3_hash_none, NULL, host, region,
		access_key, secret_key);
}

void
chttp_test_cmd_chttp_take_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_ERROR(!chttp->error, "chttp error not found");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "chttp error %s", chttp_error_msg(chttp));

	chttp_finish(chttp);

	chttp->error = 0;
}

void
chttp_test_cmd_chttp_reset(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_context *chttp = _test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_context_reset(chttp);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "context reset");
}

#define _CHTTP_FLAG_NAME(name, var)						\
char *										\
chttp_test_var_chttp_##name(struct fbr_test_context *ctx)			\
{										\
	struct chttp_context *chttp;						\
	chttp = _test_context_ok(ctx);						\
										\
	if (chttp->var) {							\
		return "1";							\
	} else {								\
		return "0";							\
	}									\
}

_CHTTP_FLAG_NAME(is_gzip, gzip)
_CHTTP_FLAG_NAME(is_tls, addr.tls)
