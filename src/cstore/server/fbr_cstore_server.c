/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <sys/socket.h>

#include "fiberfs.h"
#include "chttp.h"
#include "fbr_cstore_server.h"
#include "cstore/fbr_cstore_api.h"

void
fbr_cstore_server_alloc(struct fbr_cstore *cstore, const char *address, int port, int tls)
{
	fbr_cstore_ok(cstore);
	assert(address);
	assert(port >= 0);
	static_ASSERT(FBR_CSTORE_WORKERS_ACCEPT_DEFAULT < FBR_CSTORE_WORKERS_DEFAULT);

	struct fbr_cstore_server *server = calloc(1, sizeof(*server));
	assert(server);

	server->magic = FBR_CSTORE_SERVER_MAGIC;
	server->cstore = cstore;
	server->port = port;
	server->tls = tls;

	// TODO we need to support binding on all addresses

	chttp_addr_init(&server->addr);
	int ret = chttp_tcp_listen(&server->addr, address, server->port, 16);
	fbr_ASSERT(!ret, "listen() error %d", ret);
	chttp_addr_connected(&server->addr);
	assert_zero_dev(server->addr.error);
	assert_dev(server->addr.listen);

	server->port = server->addr.listen_port;
	if (server->tls) {
		server->addr.tls = 1;
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_SERVER, FBR_REQID_CSTORE,
		"server listening on %s:%d (tls: %d)", address, server->port, server->tls);

	fbr_cstore_worker_add(cstore, _CSTORE_CONFIG.server_workers);

	static_ASSERT(FBR_CSTORE_WORKERS_ACCEPT_DEFAULT < FBR_CSTORE_WORKERS_DEFAULT);
	assert(_CSTORE_CONFIG.server_workers_accept > 0);
	assert(_CSTORE_CONFIG.server_workers_accept < _CSTORE_CONFIG.server_workers);
	for (size_t i = 0; i < _CSTORE_CONFIG.server_workers_accept; i++) {
		fbr_cstore_task_add(cstore, FBR_CSTORE_TASK_ACCEPT, server);
	}

	server->next = cstore->servers;
	cstore->servers = server;
}

void
fbr_cstore_server_accept(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_cstore_task_ok(worker->task);

	struct fbr_cstore_server *server = worker->task->param;
	fbr_cstore_server_ok(server);

	int ret = chttp_tcp_accept(&worker->remote_addr, &server->addr);

	fbr_cstore_task_add(worker->cstore, FBR_CSTORE_TASK_ACCEPT, server);

	if (ret) {
		return;
	}

	chttp_addr_connected(&worker->remote_addr);
	assert_zero_dev(worker->remote_addr.error);

	char remote[128];
	int remote_port;
	chttp_sa_string(&worker->remote_addr.sa, remote, sizeof(remote), &remote_port);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "connection made from %s:%d to %d",
		remote, remote_port, server->port);

	fbr_cstore_proc_http(worker);

	if (worker->remote_addr.state == CHTTP_ADDR_CONNECTED) {
		// TODO keep alive on a queue somewhere
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "keep alive detected");
		chttp_tcp_close(&worker->remote_addr);
	}
}

void
fbr_cstore_servers_shutdown(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_server *server = cstore->servers;
	while (server) {
		fbr_cstore_server_ok(server);
		(void)shutdown(server->addr.sock, SHUT_RDWR);
		server = server->next;
	}
}

void
fbr_cstore_servers_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	while (cstore->servers) {
		struct fbr_cstore_server *server = cstore->servers;
		fbr_cstore_server_ok(server);

		cstore->servers = server->next;

		(void)shutdown(server->addr.sock, SHUT_RDWR);
		chttp_tcp_close(&server->addr);

		fbr_zero(server);
		free(server);
	}
}
