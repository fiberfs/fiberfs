/*
 * Copyright (c) 2021 chttp
 *
 */

#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

#include "compress/chttp_gzip.h"
#include "test/fbr_test.h"
#include "test/chttp_test_cmds.h"
#include "tls/chttp_tls.h"
#include "utils/fbr_chash.h"

#define _SERVER_IP_DEFAULT			"127.0.0.1"
#define _SERVER_JOIN_TIMEOUT_MS			2500
#define _SERVER_MAX_RANDOM_BODYLEN		(2 * 1024 * 1024)
#define _SERVER_MAX_RANDOM_CHUNKLEN		(32 * 1024)

struct _server_cmdentry {
	unsigned int				magic;
#define _SERVER_CMDENTRY			0xA50DBA3C

	TAILQ_ENTRY(_server_cmdentry)		entry;

	struct fbr_test_cmd			cmd;
};

struct chttp_test_server {
	unsigned int				magic;
#define _SERVER_MAGIC				0xF3969B6A

	struct fbr_test_context			*ctx;

	pthread_t				thread;

	pthread_mutex_t				cmd_lock;
	pthread_cond_t				cmd_signal;
	TAILQ_HEAD(, _server_cmdentry)		cmd_list;

	volatile int				stop;
	volatile int				started;
	volatile int				stopped;

	struct chttp_addr			saddr;
	struct chttp_addr			addr;
	char					ip_str[128];
	char					port_str[16];
	int					tls;

	struct chttp_context			*chttp;

	pthread_mutex_t				flush_lock;
	pthread_cond_t				flush_signal;
};

#define _server_ok(server)	\
	fbr_magic_check(server, _SERVER_MAGIC)

static void *_server_thread(void *arg);

static inline struct chttp_test_server *
_server_context_ok(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	fbr_test_ERROR(!ctx->chttp_test->server, "server context does not exist");
	_server_ok(ctx->chttp_test->server);
	return ctx->chttp_test->server;
}

static inline void
_server_LOCK(struct chttp_test_server *server)
{
	_server_ok(server);
	pt_assert(pthread_mutex_lock(&server->cmd_lock));
}

static inline void
_server_UNLOCK(struct chttp_test_server *server)
{
	_server_ok(server);
	pt_assert(pthread_mutex_unlock(&server->cmd_lock));
}

static inline void
_server_SIGNAL(struct chttp_test_server *server)
{
	_server_ok(server);
	pt_assert(pthread_cond_signal(&server->cmd_signal));
}

static inline void
_server_WAIT(struct chttp_test_server *server)
{
	_server_ok(server);
	pt_assert(pthread_cond_wait(&server->cmd_signal, &server->cmd_lock));
}

static void
_server_cmdentry_free(struct _server_cmdentry *cmdentry)
{
	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);

	free((char*)cmdentry->cmd.name);

	for (size_t i = 0; i < cmdentry->cmd.param_count; i++) {
		free((char*)cmdentry->cmd.params[i].value);
	}

	fbr_zero(cmdentry);
	free(cmdentry);
}

static struct _server_cmdentry *
_server_cmdentry_alloc(void)
{
	struct _server_cmdentry *cmdentry = calloc(1, sizeof(*cmdentry));
	assert(cmdentry);

	cmdentry->magic = _SERVER_CMDENTRY;

	return cmdentry;
}

static void
_server_cmd_async(struct chttp_test_server *server, struct fbr_test_cmd *cmd)
{
	_server_ok(server);
	assert(cmd);
	assert(cmd->func);
	assert_zero(cmd->async);

	struct _server_cmdentry *cmdentry = _server_cmdentry_alloc();

	cmdentry->cmd.magic = FBR_TEST_CMD_MAGIC;
	cmdentry->cmd.name = strdup(cmd->name);
	cmdentry->cmd.param_count = cmd->param_count;
	cmdentry->cmd.func = cmd->func;
	cmdentry->cmd.async = 1;

	for (size_t i = 0; i < cmd->param_count; i++) {
		cmdentry->cmd.params[i].value = strdup(cmd->params[i].value);
		cmdentry->cmd.params[i].len = cmd->params[i].len;
		cmdentry->cmd.params[i].v_const = cmd->params[i].v_const;
	}

	_server_LOCK(server);

	TAILQ_INSERT_TAIL(&server->cmd_list, cmdentry, entry);

	_server_SIGNAL(server);
	_server_UNLOCK(server);
}

static void
_server_finish(struct fbr_test_context *ctx)
{
	struct chttp_test_server *server = _server_context_ok(ctx);

	_server_LOCK(server);

	assert(server->started);
	assert_zero(server->stop);
	assert_zero(server->stopped);
	server->stop = 1;

	_server_SIGNAL(server);
	_server_UNLOCK(server);

	unsigned long timeout = _SERVER_JOIN_TIMEOUT_MS;

	int ret = fbr_test_join_thread(server->thread, &server->stopped, &timeout);
	if (ret) {
		fbr_test_log(ctx, FBR_LOG_VERBOSE, "ERROR: server thread is blocked");
		exit(1);
	}

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* thread joined");

	pt_assert(pthread_mutex_destroy(&server->cmd_lock));
	pt_assert(pthread_mutex_destroy(&server->flush_lock));
	pt_assert(pthread_cond_destroy(&server->cmd_signal));
	pt_assert(pthread_cond_destroy(&server->flush_signal));

	struct _server_cmdentry *cmdentry, *temp;
	size_t finished = 0;

	TAILQ_FOREACH_SAFE(cmdentry, &server->cmd_list, entry, temp) {
		assert(cmdentry->magic == _SERVER_CMDENTRY);

		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* unfinished cmd found %s",
			cmdentry->cmd.name);

		_server_cmdentry_free(cmdentry);

		finished++;
	}

	assert(TAILQ_EMPTY(&server->cmd_list));
	fbr_test_ERROR(finished, "all commands must be finished");

	if (server->chttp) {
		fbr_test_ERROR(server->chttp->error, "server error detected (%s)",
			chttp_error_msg(server->chttp));

		chttp_finish(server->chttp);
		chttp_context_free(server->chttp);
		server->chttp = NULL;
	}

	if (server->saddr.state == CHTTP_ADDR_CONNECTED) {
		chttp_tcp_close(&server->saddr);
	}

	chttp_addr_closed(&server->saddr);

	if (server->addr.state == CHTTP_ADDR_CONNECTED) {
		chttp_tcp_close(&server->addr);
	}

	chttp_addr_closed(&server->addr);

	fbr_zero(server);
	free(server);

	ctx->chttp_test->server = NULL;
}

static void
_gzip_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	assert(ctx->chttp_test->gzip);

	fbr_gzip_free(ctx->chttp_test->gzip);

	ctx->chttp_test->gzip = NULL;
}

static void
_server_init_socket(struct chttp_test_server *server)
{
	_server_ok(server);
	chttp_addr_closed(&server->saddr);

	int val = chttp_tcp_listen(&server->saddr, server->ip_str, 0, 0);
	fbr_test_ERROR(val || server->saddr.error, "*SERVER* server listen");

	if (server->tls) {
		server->saddr.tls = 1;
	}

	fbr_bprintf(server->port_str, "%d", server->saddr.listen_port);

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* socket port: %d",
		server->saddr.listen_port);
}

void
chttp_test_cmd_server_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	chttp_test_context_ok(ctx->chttp_test);
	fbr_test_ERROR(cmd->param_count > 2, "too many parameters");
	fbr_test_ERROR(ctx->chttp_test->server != NULL, "server context exists");

	struct chttp_test_server *server = calloc(1, sizeof(*server));
	assert(server);

	server->magic = _SERVER_MAGIC;
	server->ctx = ctx;
	chttp_addr_init(&server->saddr);
	chttp_addr_init(&server->addr);
	TAILQ_INIT(&server->cmd_list);
	pt_assert(pthread_mutex_init(&server->cmd_lock, NULL));
	pt_assert(pthread_mutex_init(&server->flush_lock, NULL));
	pt_assert(pthread_cond_init(&server->cmd_signal, NULL));
	pt_assert(pthread_cond_init(&server->flush_signal, NULL));

	if (cmd->param_count >= 1) {
		fbr_test_ERROR_string(cmd->params[0].value);
		fbr_bprintf(server->ip_str, "%s", cmd->params[0].value);
	} else {
		fbr_bprintf(server->ip_str, "%s", _SERVER_IP_DEFAULT);
	}
	fbr_test_ERROR_string(server->ip_str);

	if (cmd->param_count >= 2) {
		fbr_test_ERROR_string(cmd->params[1].value);
		if (!strcmp(cmd->params[1].value, "1")) {
			server->tls = 1;
			fbr_test_ERROR(!chttp_tls_enabled(), "TLS not enabled");
		}
	}

	_server_LOCK(server);

	// Start the server thread
	pt_assert(pthread_create(&server->thread, NULL, _server_thread, server));

	// Wait for it to ack
	assert_zero(server->started);
	_server_WAIT(server);
	assert(server->started);

	_server_UNLOCK(server);

	_server_init_socket(server);

	ctx->chttp_test->server = server;

	fbr_test_register_finish(ctx, "server", _server_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*SERVER* init completed");
}

void
chttp_test_cmd_server_accept(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_addr_connected(&server->saddr);
	chttp_addr_closed(&server->addr);

	if (fbr_test_is_valgrind()) {
		fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE,
			"valgrind detected, bumping server timeouts");
		server->addr.timeout_connect_ms = 60000;
		server->addr.timeout_transfer_ms = 120000;
	}

	int ret = chttp_tcp_accept(&server->addr, &server->saddr);

	fbr_test_ERROR(ret || server->addr.error, "*SERVER* accept error %d",
		server->addr.error);

	if (server->addr.tls) {
		fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* TLS established");
	}

	chttp_addr_connected(&server->addr);

	char remote[128];
	int remote_port;
	chttp_sa_string(&server->addr.sa, remote, sizeof(remote), &remote_port);

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* remote client %s:%d",
		remote, remote_port);
}

void
chttp_test_cmd_server_close(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_addr_connected(&server->addr);

	chttp_tcp_close(&server->addr);
	chttp_addr_closed(&server->addr);
}

char *
chttp_test_var_server_host(struct fbr_test_context *ctx)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	chttp_addr_connected(&server->saddr);
	fbr_test_ERROR_string(server->ip_str);

	return server->ip_str;
}

char *
chttp_test_var_server_port(struct fbr_test_context *ctx)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	chttp_addr_connected(&server->saddr);
	fbr_test_ERROR_string(server->port_str);

	return server->port_str;
}

char *
chttp_test_var_server_tls(struct fbr_test_context *ctx)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	chttp_addr_connected(&server->saddr);

	if (server->tls) {
		return "1";
	}

	return "0";
}

void
chttp_test_cmd_server_read_request(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	struct fbr_test *test = fbr_test_convert(server->ctx);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_addr_connected(&server->addr);

	if (server->chttp) {
		fbr_test_ERROR(server->chttp->error, "server error detected (%s)",
			chttp_error_msg(server->chttp));

		chttp_context_free(server->chttp);

		server->chttp = NULL;
	}

	server->chttp = malloc(sizeof(struct chttp_context));
	assert(server->chttp);
	chttp_context_init_buf(server->chttp, sizeof(struct chttp_context));

	server->chttp->do_free = 1;

	chttp_addr_move(&server->chttp->addr, &server->addr);

	chttp_parse(server->chttp, CHTTP_REQUEST);
	assert(server->chttp->request);

	if (server->chttp->sent_100) {
		fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* 100 acked");
	}

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* body ready");

	if (test->verbocity == FBR_LOG_VERY_VERBOSE) {
		fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* dpage dump");
		chttp_context_debug(server->chttp);
	}

	if (server->chttp->state == CHTTP_STATE_IDLE) {
		chttp_addr_move(&server->addr, &server->chttp->addr);
		chttp_addr_connected(&server->addr);
	} else {
		assert(server->chttp->state == CHTTP_STATE_BODY);
	}
}

static void
_server_match_header(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	chttp_context_ok(server->chttp);
	assert(cmd);
	assert(cmd->name);
	assert(cmd->async);

	const char *header, *header_value, *expected, *dup;
	header = header_value = expected = dup = NULL;
	int sub = 0;

	if (!strcmp(cmd->name, "server_method_match")) {
		assert(cmd->param_count == 1);

		header = "_METHOD";
		expected = cmd->params[0].value;

		header_value = chttp_header_get_method(server->chttp);
	} else if (!strcmp(cmd->name, "server_url_match")) {
		assert(cmd->param_count == 1);

		header = "_URL";
		expected = cmd->params[0].value;

		header_value = chttp_header_get_url(server->chttp);
	} else if (!strcmp(cmd->name, "server_url_submatch")) {
		assert(cmd->param_count == 1);

		header = "_URL";
		expected = cmd->params[0].value;

		header_value = chttp_header_get_url(server->chttp);
		sub = 1;
	} else if (!strcmp(cmd->name, "server_version_match")) {
		assert(cmd->param_count == 1);

		header = "_VERSION";
		expected = cmd->params[0].value;

		header_value = chttp_header_get_version(server->chttp);
	} else if (!strcmp(cmd->name, "server_header_match")) {
		assert(cmd->param_count == 2);

		fbr_test_unescape(&cmd->params[1]);

		header = cmd->params[0].value;
		expected = cmd->params[1].value;
		header_value = chttp_header_get(server->chttp, header);
		dup = chttp_header_get_pos(server->chttp, header, 1);
	} else if (!strcmp(cmd->name, "server_header_submatch")) {
		assert(cmd->param_count == 2);

		fbr_test_unescape(&cmd->params[1]);

		header = cmd->params[0].value;
		expected = cmd->params[1].value;
		header_value = chttp_header_get(server->chttp, header);
		dup = chttp_header_get_pos(server->chttp, header, 1);
		sub = 1;
	} else if (!strcmp(cmd->name, "server_header_exists")) {
		assert(cmd->param_count == 1);

		header = cmd->params[0].value;
		expected = NULL;
		header_value = chttp_header_get(server->chttp, header);
		dup = chttp_header_get_pos(server->chttp, header, 1);
	} else if (!strcmp(cmd->name, "server_header_not_exists")) {
		assert(cmd->param_count == 1);

		header = cmd->params[0].value;
		header_value = chttp_header_get(server->chttp, header);

		fbr_test_ERROR(header_value != NULL, "header %s exists", header);

		fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* header not exists %s",
			header);

		return;
	}else {
		assert_zero("INVALID SERVER MATCH");
	}

	fbr_test_ERROR(!header_value, "header %s not found", header);
	fbr_test_ERROR(dup != NULL, "duplicate %s header found", header);

	if (!expected) {
		fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* header exists %s",
			header);
		return;
	}

	if (sub) {
		fbr_test_ERROR(!strstr(header_value, expected), "value %s not found in header "
			"%s:%s", expected, header, header_value);
	} else {
		fbr_test_ERROR(strcmp(header_value, expected), "headers dont match, found %s:%s, "
			"expected %s", header, header_value, expected);
	}

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* headers match %s:%s%s%s%s",
		header, header_value, sub ? " (" : "", sub ? expected : "", sub ? ")" : "");
}

void
chttp_test_cmd_server_method_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_url_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_url_submatch(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_version_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_submatch(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 2);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_exists(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

void
chttp_test_cmd_server_header_not_exists(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	cmd->func = &_server_match_header;

	_server_cmd_async(server, cmd);
}

static void
_server_body_match(struct chttp_test_server *server, const char *match, int submatch)
{
	_server_ok(server);
	chttp_context_ok(server->chttp);
	chttp_addr_connected(&server->chttp->addr);

	char body[1024], gzip_buf[1024];
	struct fbr_gzip *gzip;

	if (server->chttp->gzip && fbr_gzip_enabled()) {
		gzip = fbr_gzip_inflate_alloc();
		chttp_gzip_register(server->chttp, gzip, gzip_buf, sizeof(gzip_buf));
	}

	size_t body_len = 0;
	size_t read_len;

	do {
		read_len = chttp_body_read(server->chttp, body + body_len,
			sizeof(body) - 1 - body_len);
		body_len += read_len;
		assert(body_len < sizeof(body));
	} while (read_len > 0);

	body[body_len] = '\0';

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*BODY* '%s':%zu", body, body_len);

	if (match) {
		if (submatch) {
			fbr_test_ERROR(!strstr(body, match), "body doesnt submatch");
		} else {
			fbr_test_ERROR(strcmp(body, match), "body doesnt match");
		}
	}

	assert(server->chttp->state == CHTTP_STATE_IDLE);

	chttp_addr_move(&server->addr, &server->chttp->addr);
	chttp_addr_connected(&server->addr);
}

void
chttp_test_cmd_server_body_match(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_body_match(server, cmd->params[0].value, 0);
}

void
chttp_test_cmd_server_body_submatch(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_body_match(server, cmd->params[0].value, 1);
}

void
chttp_test_cmd_server_body_read(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_body_match(server, NULL, 0);
}

static void
_server_send_buf(struct chttp_test_server *server, const void *buf, size_t len)
{
	_server_ok(server);
	chttp_addr_connected(&server->addr);

	chttp_tcp_send(&server->addr, buf, len);
	fbr_test_ERROR(server->addr.error, "server send error %d", server->addr.error);
}

static void __chttp_attr_printf
_server_send_printf(struct chttp_test_server *server, const char *fmt, ...)
{
	_server_ok(server);

	va_list ap;
	char buf[256];

	va_start(ap, fmt);

	size_t len = vsnprintf(buf, sizeof(buf), fmt, ap);
	assert(len < sizeof(buf));

	_server_send_buf(server, buf, len);

	va_end(ap);
}

static void
_server_send_response(struct chttp_test_server *server, struct fbr_test_cmd *cmd,
    int H1_1, int partial)
{
	_server_ok(server);
	chttp_context_ok(server->chttp);
	assert(server->chttp->state == CHTTP_STATE_IDLE);
	chttp_addr_connected(&server->addr);
	assert(cmd);
	assert(cmd->param_count <= 4);

	long status = 200;
	char *reason = "OK";
	char *body = "";
	size_t body_len = 0;
	int do_gzip = 0;

	if (cmd->param_count >= 1) {
		status = fbr_test_parse_long(cmd->params[0].value);
		assert(status > 0 && status < 1000);
	}
	if (cmd->param_count >= 2) {
		fbr_test_ERROR_string(cmd->params[1].value);
		reason = cmd->params[1].value;
	}
	if (cmd->param_count >= 3) {
		assert_zero(partial);
		body = cmd->params[2].value;
		body_len = cmd->params[2].len;
	}
	if (cmd->param_count >= 4) {
		fbr_test_ERROR_string(cmd->params[3].value);
		if (!strcmp(cmd->params[3].value, "1")) {
			char gzip_buf[1024];
			assert(body_len < sizeof(gzip_buf));

			struct fbr_gzip gzip;
			do_gzip = 1;
			fbr_gzip_deflate_init(&gzip);

			fbr_gzip_flate(&gzip, body, body_len, gzip_buf, sizeof(gzip_buf),
				&body_len, 1);
			assert(gzip.status == FBR_GZIP_DONE);
			assert(body_len > 0);

			body = gzip_buf;

			fbr_gzip_free(&gzip);
		}
	}

	_server_send_printf(server, "HTTP/1.%c %ld %s\r\n", H1_1 ? '1' : '0', status, reason);
	_server_send_printf(server, "Server: chttp_test %s\r\n", CHTTP_VERSION);
	_server_send_printf(server, "Date: // TODO\r\n");

	if (do_gzip) {
		_server_send_printf(server, "Content-Encoding: gzip\r\n");
	}

	if (partial) {
		return;
	}

	if (H1_1) {
		_server_send_printf(server, "Content-Length: %zu\r\n\r\n", body_len);
	} else {
		_server_send_printf(server, "\r\n");
	}

	if (body_len > 0) {
		_server_send_buf(server, body, body_len);
	}

	if (!H1_1) {
		chttp_tcp_close(&server->addr);
		chttp_addr_closed(&server->addr);
	}
}

void
chttp_test_cmd_server_send_response(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	assert(cmd);
	fbr_test_ERROR(cmd->param_count > 4, "too many parameters");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_response(server, cmd, 1, 0);
}

void
chttp_test_cmd_server_send_response_H1_0(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	assert(cmd);
	fbr_test_ERROR(cmd->param_count > 4, "too many parameters");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_response(server, cmd, 0, 0);
}

void
chttp_test_cmd_server_send_response_partial(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	assert(cmd);
	fbr_test_ERROR(cmd->param_count > 2, "too many parameters");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_response(server, cmd, 1, 1);
}

void
chttp_test_cmd_server_send_header(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	fbr_test_unescape(&cmd->params[0]);

	_server_send_printf(server, "%s\r\n", cmd->params[0].value);
}

void
chttp_test_cmd_server_send_header_done(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_printf(server, "\r\n");
}

void
chttp_test_cmd_server_enable_gzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	fbr_test_ERROR(ctx->chttp_test->gzip != NULL, "gzip already initialized");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	ctx->chttp_test->gzip = fbr_gzip_deflate_alloc();
	assert(ctx->chttp_test->gzip);

	chttp_gzip_register(NULL, ctx->chttp_test->gzip, ctx->chttp_test->gzip_buf,
		sizeof(ctx->chttp_test->gzip_buf));

	fbr_test_register_finish(ctx, "gzip", _gzip_finish);

	_server_send_printf(server, "Content-Encoding: gzip\r\n");
}

void
chttp_test_cmd_server_start_chunked(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	_server_send_printf(server, "Transfer-Encoding: chunked\r\n\r\n");
}

void
chttp_test_cmd_server_send_chunked(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	fbr_test_unescape(&cmd->params[0]);

	_server_send_printf(server, "%x\r\n%s\r\n", (unsigned int)cmd->params[0].len,
		cmd->params[0].value);
}

void
chttp_test_cmd_server_send_chunked_gzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	assert(cmd);
	fbr_test_ERROR(cmd->param_count != 1, "bad parameters");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	assert(ctx->chttp_test->gzip);

	fbr_test_unescape(&cmd->params[0]);

	if (cmd->params[0].len == 0) {
		chttp_gzip_send_chunk(ctx->chttp_test->gzip, &server->addr, NULL, 0);
	} else {
		chttp_gzip_send_chunk(ctx->chttp_test->gzip, &server->addr, cmd->params[0].value,
			cmd->params[0].len);
	}
}

void
chttp_test_cmd_server_end_chunked(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	if (ctx->chttp_test->gzip) {
		chttp_gzip_send_chunk(ctx->chttp_test->gzip, &server->addr, NULL, 0);
	}

	_server_send_printf(server, "0\r\n\r\n");
}

void
chttp_test_cmd_server_send_raw(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	fbr_test_unescape(&cmd->params[0]);

	_server_send_buf(server, cmd->params[0].value, cmd->params[0].len);
}

void
chttp_test_cmd_server_send_raw_sock(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	chttp_addr_connected(&server->addr);

	fbr_test_unescape(&cmd->params[0]);

	ssize_t ret = send(server->addr.sock, cmd->params[0].value, cmd->params[0].len,
		MSG_NOSIGNAL);
	assert(ret >= 0 && (size_t)ret == cmd->params[0].len);
}

void
chttp_test_cmd_server_send_random_body(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count > 3, "Too many params");

	struct fbr_gzip gzip;
	long bodylen = -1;
	long chunklen = -1;
	int do_gzip = 0;

	if (cmd->param_count > 0) {
		bodylen = fbr_test_parse_long(cmd->params[0].value);
	}
	if (cmd->param_count > 1) {
		chunklen = fbr_test_parse_long(cmd->params[1].value);
	}
	if (cmd->param_count > 2) {
		do_gzip = fbr_test_parse_long(cmd->params[2].value) > 0 ? 1 : 0;
	}

	fbr_test_ERROR(do_gzip && !chunklen, "gzip requires a valid chunklen");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	fbr_test_random_seed();
	struct fbr_md5_ctx md5;
	fbr_md5_init(&md5);

	if (bodylen < 0) {
		bodylen = fbr_test_gen_random(0, _SERVER_MAX_RANDOM_BODYLEN);
	}

	if (do_gzip) {
		fbr_gzip_deflate_init(&gzip);
		chttp_gzip_register(NULL, &gzip, ctx->chttp_test->gzip_buf,
			sizeof(ctx->chttp_test->gzip_buf));

		_server_send_printf(server, "Content-Encoding: gzip\r\n");
	}

	if (chunklen) {
		_server_send_printf(server, "Transfer-Encoding: chunked\r\n\r\n");
	} else {
		_server_send_printf(server, "Content-Length: %zd\r\n\r\n", bodylen);
	}

	size_t sent = 0;
	size_t chunks = 0, subchunks = 0;
	assert(bodylen >= 0);

	while (sent < (size_t)bodylen) {
		size_t send_size;
		if (chunklen < 0) {
			send_size = fbr_test_gen_random(1, _SERVER_MAX_RANDOM_CHUNKLEN);
		} else if (chunklen == 0) {
			send_size = bodylen;
		} else {
			send_size = chunklen;
		}

		if (send_size > bodylen - sent) {
			send_size = bodylen - sent;
		}

		if (chunklen && !do_gzip) {
			_server_send_printf(server, "%x\r\n", (unsigned int)send_size);
		}

		size_t partial = 0;

		while (partial < send_size) {
			uint8_t buf[8192];
			size_t len = send_size - partial;
			if (len > sizeof(buf)) {
				len = sizeof(buf);
			}

			fbr_test_fill_random(buf, len);

			if (do_gzip) {
				assert(chunklen);

				chttp_gzip_send_chunk(&gzip, &server->addr, buf, len);
			} else {
				_server_send_buf(server, buf, len);
			}

			fbr_md5_update(&md5, buf, len);

			partial += len;
			subchunks++;
		}

		assert(partial == send_size);
		sent += partial;

		chunks++;

		if (chunklen && !do_gzip) {
			_server_send_printf(server, "\r\n");
		}
	}

	assert(sent == (size_t)bodylen);

	if (do_gzip) {
		chttp_gzip_send_chunk(&gzip, &server->addr, NULL, 0);
		fbr_gzip_free(&gzip);
	}

	if (chunklen) {
		_server_send_printf(server, "0\r\n\r\n");
	}

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* sent random body bytes %zu "
		"(%zu %zu)", sent, chunks, subchunks);

	fbr_md5_final(&md5);
	chttp_test_md5_store_server(ctx, &md5);

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* body md5 %s",
		ctx->chttp_test->md5_server);
}

void
chttp_test_cmd_server_sleep_ms(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long ms = fbr_test_parse_long(cmd->params[0].value);
	fbr_test_ERROR(ms < 0, "invalid sleep time");

	if (!cmd->async) {
		_server_cmd_async(server, cmd);
		return;
	}

	fbr_test_sleep_ms(ms);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*SERVER* slept %ldms", ms);
}

void
chttp_test_cmd_server_flush_async(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	struct chttp_test_server *server = _server_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (cmd->async) {
		pt_assert(pthread_mutex_lock(&server->flush_lock));

		pt_assert(pthread_cond_signal(&server->flush_signal));
		fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* flush signal sent");

		pt_assert(pthread_mutex_unlock(&server->flush_lock));

		return;
	}

	pt_assert(pthread_mutex_lock(&server->flush_lock));

	_server_cmd_async(server, cmd);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*SERVER* waiting for flush...");

	pt_assert(pthread_cond_wait(&server->flush_signal, &server->flush_lock));

	pt_assert(pthread_mutex_unlock(&server->flush_lock));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*SERVER* flushed");
}

static void
_server_cmd(struct chttp_test_server *server, struct _server_cmdentry *cmdentry)
{
	_server_ok(server);
	assert(cmdentry);
	assert(cmdentry->magic == _SERVER_CMDENTRY);
	assert(cmdentry->cmd.async);
	assert(cmdentry->cmd.func);

	cmdentry->cmd.func(server->ctx, &cmdentry->cmd);

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* thread cmd %s completed",
		cmdentry->cmd.name);
}

static void *
_server_thread(void *arg)
{
	struct chttp_test_server *server = arg;
	_server_ok(server);

	struct fbr_test_context *test_ctx = fbr_test_get_ctx();
	fbr_test_ok(test_ctx->test);

	_server_LOCK(server);

	// Ack the server init
	server->started = 1;
	_server_SIGNAL(server);

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* thread started");

	while (!server->stop && !test_ctx->test->error) {
		if (TAILQ_EMPTY(&server->cmd_list)) {
			_server_WAIT(server);
			continue;
		}

		// Grab work
		assert(!TAILQ_EMPTY(&server->cmd_list));
		struct _server_cmdentry *cmdentry = TAILQ_FIRST(&server->cmd_list);
		assert(cmdentry);
		assert(cmdentry->magic == _SERVER_CMDENTRY);
		TAILQ_REMOVE(&server->cmd_list, cmdentry, entry);

		_server_UNLOCK(server);

		_server_cmd(server, cmdentry);
		_server_cmdentry_free(cmdentry);

		_server_LOCK(server);
	}

	assert_zero(server->stopped);
	server->stopped = 1;

	_server_UNLOCK(server);

	fbr_test_log(server->ctx, FBR_LOG_VERY_VERBOSE, "*SERVER* thread finished");

	return NULL;
}
