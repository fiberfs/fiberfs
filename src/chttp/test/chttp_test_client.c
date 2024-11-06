/*
 * Copyright (c) 2021 chttp
 *
 */

#include "test/fbr_test.h"
#include "test/fbr_test_cmds.h"
#include "test/chttp_test_cmds.h"
#include "compress/chttp_gzip.h"
#include "network/chttp_tcp_pool.h"
#include "tls/chttp_tls.h"

#include <stdlib.h>

static inline void
_test_context_ok(struct fbr_test_context *ctx)
{
	assert(ctx);
	fbr_test_ERROR(!ctx->chttp, "chttp context does not exist");
	chttp_context_ok(ctx->chttp);
	fbr_test_ok(fbr_test_convert(ctx));
}

static void
_test_client_finish(struct fbr_test_context *ctx)
{
	size_t allocs = 0;
	struct chttp_dpage *dpage;

	assert(ctx);
	fbr_test_ERROR(!ctx->chttp, "chttp context does not exist");
	chttp_context_ok(ctx->chttp);
	fbr_test_ERROR(ctx->chttp->error, "chttp context has an error (%s)",
		chttp_error_msg(ctx->chttp));

	if (ctx->chttp->do_free) {
		allocs++;
	}

	dpage = ctx->chttp->dpage;
	while(dpage) {
		if (dpage->free) {
			allocs++;
		}
		dpage = dpage->next;
	}

	chttp_context_free(ctx->chttp);
	ctx->chttp = NULL;

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "context contained %zu allocations", allocs);

	chttp_tcp_pool_close();

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "tcp pool cleanup");

	chttp_tls_free();

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "TLS shutdown");
}

void
chttp_test_cmd_chttp_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);

	fbr_test_ERROR_param_count(cmd, 0);
	fbr_test_ERROR(ctx->chttp != NULL, "chttp context exists");

	ctx->chttp = &ctx->chttp_static;

	chttp_context_init(ctx->chttp);
	chttp_context_ok(ctx->chttp);

	fbr_test_register_finish(ctx, "chttp_client", _test_client_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_init_dynamic(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long size = 0;

	assert(ctx);

	fbr_test_ERROR(cmd->param_count > 1, "too many parameters");
	fbr_test_ERROR(ctx->chttp != NULL, "chttp context exists");

	if (cmd->param_count == 1) {
		size = fbr_test_parse_long(cmd->params[0].value);
		fbr_test_ERROR(size <= 0, "chttp size must be greater than 0");
	}

	_DEBUG_CHTTP_DPAGE_MIN_SIZE = (size_t)size;

	ctx->chttp = chttp_context_alloc();
	chttp_context_ok(ctx->chttp);

	fbr_test_register_finish(ctx, "chttp_client", _test_client_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "context initialized");
}

void
chttp_test_cmd_chttp_timeout_connect_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int timeout;

	_test_context_ok(ctx);
	chttp_addr_ok(&ctx->chttp->addr);
	fbr_test_ERROR_param_count(cmd, 1);

	timeout = (int)fbr_test_parse_long(cmd->params[0].value);

	fbr_test_ERROR(ctx->chttp->addr.state != CHTTP_ADDR_RESOLVED, "Address must be resolved first");

	ctx->chttp->addr.timeout_connect_ms = timeout;
}

void
chttp_test_cmd_chttp_timeout_transfer_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	int timeout;

	_test_context_ok(ctx);
	chttp_addr_ok(&ctx->chttp->addr);
	fbr_test_ERROR_param_count(cmd, 1);

	timeout = (int)fbr_test_parse_long(cmd->params[0].value);

	fbr_test_ERROR(ctx->chttp->addr.state != CHTTP_ADDR_RESOLVED, "Address must be resolved first");

	ctx->chttp->addr.timeout_transfer_ms = timeout;
}

void
chttp_test_cmd_chttp_version(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long version;

	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	version = fbr_test_parse_long(cmd->params[0].value);

	switch (version) {
		case 10:
			chttp_set_version(ctx->chttp, CHTTP_H_VERSION_1_0);
			return;
		case 11:
			chttp_set_version(ctx->chttp, CHTTP_H_VERSION_1_1);
			return;
	}

	fbr_test_ERROR(1, "unsupported chttp version %ld", version);
}

void
chttp_test_cmd_chttp_method(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_set_method(ctx->chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_url(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_set_url(ctx->chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_add_header(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	fbr_test_unescape(&cmd->params[1]);

	chttp_header_add(ctx->chttp, cmd->params[0].value, cmd->params[1].value);
}

void
chttp_test_cmd_chttp_delete_header(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_header_delete(ctx->chttp, cmd->params[0].value);
}

void
chttp_test_cmd_chttp_connect(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long port;
	int tls = 0, outport;
	char name[256];

	_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 3, "too many parameters");
	fbr_test_ERROR(cmd->param_count < 2, "missing parameters");
	fbr_test_ERROR_string(cmd->params[0].value);
	fbr_test_ERROR_string(cmd->params[1].value);

	if (cmd->param_count >= 3) {
		fbr_test_ERROR_string(cmd->params[2].value);
		if (!strcmp(cmd->params[2].value, "1")) {
			tls = 1;
		}
	}

	port = fbr_test_parse_long(cmd->params[1].value);
	fbr_test_ERROR(port <= 0 || port > UINT16_MAX, "invalid port");

	chttp_connect(ctx->chttp, cmd->params[0].value, cmd->params[0].len, port, tls);

	fbr_test_ERROR(ctx->chttp->error, "connection failed: %s", chttp_error_msg(ctx->chttp));

	chttp_sa_string(&ctx->chttp->addr.sa, name, sizeof(name), &outport);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "lookup made to %s:%ld => %s:%d",
		cmd->params[0].value, port, name, outport);
}

char *
chttp_test_var_chttp_reused(struct fbr_test_context *ctx)
{
	_test_context_ok(ctx);
	chttp_addr_ok(&ctx->chttp->addr);

	if (ctx->chttp->addr.reused) {
		return "1";
	} else {
		return "0";
	}
}

void
chttp_test_cmd_chttp_new_connection(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	ctx->chttp->new_conn = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "new connection set");
}

void
chttp_test_cmd_chttp_enable_gzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	ctx->chttp->gzip = 1;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "gzip enabled");
}

void
chttp_test_cmd_chttp_send_only(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_send(ctx->chttp);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request sent");
}

void
chttp_test_cmd_chttp_send_body(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	chttp_body_send(ctx->chttp, cmd->params[0].value, cmd->params[0].len);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request body sent");
}

void
chttp_test_cmd_chttp_send_body_chunkgzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_gzip gzip;
	char buf[1024];

	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);
	chttp_context_ok(ctx->chttp);
	assert(ctx->chttp->state == CHTTP_STATE_SENT);
	chttp_addr_connected(&ctx->chttp->addr);

	chttp_gzip_deflate_init(&gzip);
	chttp_gzip_register(NULL, &gzip, buf, sizeof(buf));

	chttp_gzip_send_chunk(&gzip, &ctx->chttp->addr, cmd->params[0].value,
		cmd->params[0].len);
	chttp_gzip_send_chunk(&gzip, &ctx->chttp->addr, NULL, 0);
	chttp_tcp_send(&ctx->chttp->addr, "0\r\n\r\n", 5);

	chttp_gzip_free(&gzip);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request body sent chunked gzip");
}

void
chttp_test_cmd_chttp_receive(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct fbr_test *test;

	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	test = fbr_test_convert(ctx);

	chttp_receive(ctx->chttp);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "request received");

	if (test->verbocity == FBR_LOG_VERY_VERBOSE) {
		printf("--- ");
		chttp_context_debug(ctx->chttp);
	}
}

void
chttp_test_cmd_chttp_send(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_test_cmd_chttp_send_only(ctx, cmd);
	fbr_test_ERROR(ctx->chttp->error, "chttp send error");

	chttp_test_cmd_chttp_receive(ctx, cmd);
}

void
chttp_test_cmd_chttp_status_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long status;

	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	status = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(status <= 0 || status > 999, "invalid status");

	fbr_test_ERROR(ctx->chttp->status != status,
		"invalid status (wanted %ld, found %d)", status, ctx->chttp->status);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "status OK (%ld)", status);
}

static void
_test_header_match(struct fbr_test_context *ctx, const char *header, const char *expected,
    int sub)
{
	const char *header_value, *dup;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	assert(header);

	header_value = chttp_header_get(ctx->chttp, header);
	fbr_test_ERROR(!header_value, "header %s not found", header);

	dup = chttp_header_get_pos(ctx->chttp, header, 1);
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

	_test_header_match(ctx, CHTTP_HEADER_REASON, cmd->params[0].value, 0);
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
	long version;
	enum chttp_version expected = 0;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	fbr_test_ERROR_param_count(cmd, 1);

	version = fbr_test_parse_long(cmd->params[0].value);

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

	fbr_test_ERROR(expected != ctx->chttp->version, "version mismatch, expected %d, found %d",
		expected, ctx->chttp->version);
}

static void
_test_body_match(struct fbr_test_context *ctx, const char *expected, int sub, size_t size)
{
	char *body, gzip_buf[4096];
	size_t read, body_len, old_size, calls;
	struct chttp_gzip *gzip;

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	fbr_test_ERROR(ctx->chttp->state != CHTTP_STATE_BODY, "chttp no body found");

	body = NULL;
	body_len = 0;
	calls = 0;

	if (size == 0) {
		size = 1024;
	}

	if (ctx->chttp->gzip && chttp_gzip_enabled()) {
		gzip = chttp_gzip_inflate_alloc();
		chttp_gzip_register(ctx->chttp, gzip, gzip_buf, sizeof(gzip_buf));
	}

	do {
		if (calls) {
			old_size = size;
			size *= 2;
			assert(size / 2 == old_size);
		}

		body = realloc(body, size + 1);
		assert(body);

		read = chttp_body_read(ctx->chttp, body + body_len, size - body_len);

		// TODO test
		if (ctx->chttp->state == CHTTP_STATE_BODY) {
			assert(read > 0);
		}

		body_len += read;
		calls++;
	} while (read);

	assert(ctx->chttp->state > CHTTP_STATE_BODY);

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "read %zu body bytes in %zu call(s)",
		body_len, calls);

	if (!expected) {
		free(body);
		return;
	}

	fbr_test_ERROR(ctx->chttp->error, "chttp error %s", chttp_error_msg(ctx->chttp));

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
	long size = 0;

	_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 2, "too many parameters");
	fbr_test_ERROR(cmd->param_count < 1, "missing parameters");

	if (cmd->param_count == 2) {
		size = fbr_test_parse_long(cmd->params[1].value);
		fbr_test_ERROR(size < 0, "invalid size");
	}

	_test_body_match(ctx, cmd->params[0].value, 0, size);
}

void
chttp_test_cmd_chttp_body_submatch(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	long size = 0;

	_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 2, "too many parameters");
	fbr_test_ERROR(cmd->param_count < 1, "missing parameters");

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
	struct chttp_test_md5 md5;
	uint8_t buf[8192];
	size_t body_len, len, calls;
	struct chttp_gzip *gzip;
	char gzip_buf[4096];

	_test_context_ok(ctx);
	chttp_context_ok(ctx->chttp);
	fbr_test_ERROR(ctx->chttp->state != CHTTP_STATE_BODY, "chttp no body found");
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_test_md5_init(&md5);

	body_len = 0;
	calls = 0;

	if (ctx->chttp->gzip && chttp_gzip_enabled()) {
		gzip = chttp_gzip_inflate_alloc();
		chttp_gzip_register(ctx->chttp, gzip, gzip_buf, sizeof(gzip_buf));
	}

	do {
		len = chttp_body_read(ctx->chttp, buf, sizeof(buf));

		chttp_test_md5_update(&md5, buf, len);

		body_len += len;
		calls++;
	} while (len > 0);

	assert(ctx->chttp->state > CHTTP_STATE_BODY);
	fbr_test_ERROR(ctx->chttp->error, "chttp error %s", chttp_error_msg(ctx->chttp));

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "read %zu body bytes in %zu call(s)",
		body_len, calls);

	chttp_test_md5_final(&md5);
	chttp_test_md5_store_client(ctx, &md5);

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "body md5 %s", ctx->md5_client);
}

void
chttp_test_cmd_chttp_take_error(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_context_ok(ctx->chttp);

	fbr_test_ERROR(!ctx->chttp->error, "chttp error not found");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "chttp error %s",
		chttp_error_msg(ctx->chttp));

	chttp_finish(ctx->chttp);

	ctx->chttp->error = 0;
}

void
chttp_test_cmd_chttp_reset(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	chttp_context_reset(ctx->chttp);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "context reset");
}

#define _CHTTP_FLAG_NAME(name, var)						\
char *										\
chttp_test_var_chttp_##name(struct fbr_test_context *ctx)			\
{										\
	_test_context_ok(ctx);							\
										\
	if (ctx->chttp->var) {							\
		return "1";							\
	} else {								\
		return "0";							\
	}									\
}

_CHTTP_FLAG_NAME(is_gzip, gzip)
_CHTTP_FLAG_NAME(is_tls, addr.tls)
