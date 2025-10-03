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
_get_server(int pos)
{
	fbr_cstore_ok(_CSTORE);

	struct fbr_cstore_server *server = _CSTORE->servers;
	fbr_cstore_server_ok(server);

	while (server->next && pos != 0) {
		server = server->next;
		fbr_cstore_server_ok(server);
		pos--;
	}

	return server;
}

char *
fbr_var_cstore_server_host(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, 0);
	assert(tcstore);

	struct fbr_cstore_server *server = _get_server(-1);
	chttp_addr_connected(&server->addr);

	int port;
	chttp_sa_string(&server->addr.sa, tcstore->ip_str, sizeof(tcstore->ip_str),
		&port);

	return tcstore->ip_str;
}

char *
fbr_var_cstore_server_port(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	struct fbr_test_cstore *tcstore = fbr_test_tcstore_get(ctx, 0);
	assert(tcstore);

	struct fbr_cstore_server *server = _get_server(-1);
	chttp_addr_connected(&server->addr);
	assert(server->port > 0);

	fbr_bprintf(tcstore->port_str, "%d", server->port);

	return tcstore->port_str;
}

char *
fbr_var_cstore_server_tls(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	struct fbr_cstore_server *server = _get_server(-1);
	chttp_addr_connected(&server->addr);

	if (server->tls) {
		assert(server->addr.tls);
		return "1";
	}

	return "0";
}
