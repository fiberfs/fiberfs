/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "cstore/server/fbr_cstore_server.h"

#include "test/fbr_test.h"
#include "fbr_test_cstore_cmds.h"

extern struct fbr_cstore *_CSTORE;

void
fbr_cmd_cstore_enable_server(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_cmd_ok(cmd);
	assert(cmd->param_count <= 4);

	_CSTORE_CONFIG.server = 1;

	if (cmd->param_count >= 1) {
		fbr_test_ERROR_string(cmd->params[0].value);
		fbr_bprintf(_CSTORE_CONFIG.server_address, "%s", cmd->params[0].value);
		fbr_test_logs("cstore_enable_server address: %s", _CSTORE_CONFIG.server_address);
	}
	if (cmd->param_count >= 2) {
		fbr_test_ERROR_string(cmd->params[1].value);
		_CSTORE_CONFIG.server_port = fbr_test_parse_long(cmd->params[1].value);
		assert(_CSTORE_CONFIG.server_port >= 0 && _CSTORE_CONFIG.server_port < USHRT_MAX);
		fbr_test_logs("cstore_enable_server port: %d", _CSTORE_CONFIG.server_port);
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "cstore_enable_server: %d", _CSTORE_CONFIG.server);
}

struct fbr_cstore_server *
_get_server(struct fbr_cstore *cstore, int pos)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_server *server = cstore->servers;
	fbr_cstore_server_ok(server);

	while (server->next && pos != 0) {
		server = server->next;
		fbr_cstore_server_ok(server);
		pos--;
	}

	return server;
}

static char *
_test_server_host(struct fbr_test_cstore *tcstore)
{
	fbr_magic_check(tcstore, FBR_TEST_CSTORE_MAGIC);

	struct fbr_cstore_server *server = _get_server(&tcstore->cstore, -1);
	chttp_addr_connected(&server->addr);

	int port;
	chttp_sa_string(&server->addr.sa, tcstore->ip_str, sizeof(tcstore->ip_str),
		&port);

	return tcstore->ip_str;
}

#define _CSTORE_SERVER_HOST(index)						\
char *										\
fbr_var_cstore_##index##_server_host(struct fbr_test_context *ctx)		\
{										\
	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, index);	\
	return _test_server_host(tcstore);					\
}

_CSTORE_SERVER_HOST(0)
_CSTORE_SERVER_HOST(1)
_CSTORE_SERVER_HOST(2)
_CSTORE_SERVER_HOST(3)
_CSTORE_SERVER_HOST(4)
_CSTORE_SERVER_HOST(5)

static char *
_test_server_port(struct fbr_test_cstore *tcstore)
{
	fbr_magic_check(tcstore, FBR_TEST_CSTORE_MAGIC);

	struct fbr_cstore_server *server = _get_server(&tcstore->cstore, -1);
	chttp_addr_connected(&server->addr);
	assert(server->port > 0);

	fbr_bprintf(tcstore->port_str, "%d", server->port);

	return tcstore->port_str;
}

#define _CSTORE_SERVER_PORT(index)						\
char *										\
fbr_var_cstore_##index##_server_port(struct fbr_test_context *ctx)		\
{										\
	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, index);	\
	return _test_server_port(tcstore);					\
}

_CSTORE_SERVER_PORT(0)
_CSTORE_SERVER_PORT(1)
_CSTORE_SERVER_PORT(2)
_CSTORE_SERVER_PORT(3)
_CSTORE_SERVER_PORT(4)
_CSTORE_SERVER_PORT(5)

static char *
_test_server_tls(struct fbr_test_cstore *tcstore)
{
	fbr_magic_check(tcstore, FBR_TEST_CSTORE_MAGIC);

	struct fbr_cstore_server *server = _get_server(&tcstore->cstore, -1);
	chttp_addr_connected(&server->addr);

	if (server->tls) {
		assert(server->addr.tls);
		return "1";
	}

	return "0";
}

#define _CSTORE_SERVER_TLS(index)						\
char *										\
fbr_var_cstore_##index##_server_tls(struct fbr_test_context *ctx)		\
{										\
	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, index);	\
	return _test_server_tls(tcstore);					\
}

_CSTORE_SERVER_TLS(0)
_CSTORE_SERVER_TLS(1)
_CSTORE_SERVER_TLS(2)
_CSTORE_SERVER_TLS(3)
_CSTORE_SERVER_TLS(4)
_CSTORE_SERVER_TLS(5)
