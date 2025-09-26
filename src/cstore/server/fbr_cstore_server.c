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

static void *_cstore_worker_loop(void *arg);
static void _cstore_worker_accept(struct fbr_cstore_worker *worker);

void
fbr_cstore_server_alloc(struct fbr_cstore *cstore, const char *address, int port, int tls)
{
	fbr_cstore_ok(cstore);
	assert(address);
	assert(port >= 0);

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

	server->workers_max = _CSTORE_CONFIG.server_workers;

	for (size_t i = 0; i < server->workers_max; i++) {
		pt_assert(pthread_create(&server->workers[i], NULL, _cstore_worker_loop, server));
	}

	while (server->workers_running != server->workers_max) {
		fbr_sleep_ms(0.1);
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_SERVER, FBR_REQID_CSTORE,
		"server listening on %s:%d (tls: %d)", address, server->port, server->tls);

	server->next = cstore->servers;
	cstore->servers = server;
}

static void *
_cstore_worker_loop(void *arg)
{
	assert(arg);

	struct fbr_cstore_server *server = arg;
	fbr_cstore_server_ok(server);
	fbr_cstore_ok(server->cstore);
	fbr_log_ok(server->cstore->log);

	struct fbr_cstore_worker *worker = fbr_cstore_worker_alloc(server);
	assert(worker);

	worker->thread_id = fbr_request_id_thread_gen();
	worker->thread_pos = fbr_atomic_add(&server->workers_running, 1);

	fbr_thread_name("fbr_worker");

	fbr_log_print(server->cstore->log, FBR_LOG_CS_WORKER, worker->thread_id,
		"running on port %d", server->port);

	while (!server->exit) {
		if (worker->thread_pos > server->workers_max) {
			break;
		}

		_cstore_worker_accept(worker);
	}

	fbr_cstore_worker_free(worker);

	fbr_atomic_sub(&server->workers_running, 1);

	return NULL;
}

static void
_cstore_worker_accept(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_cstore_server_ok(worker->server);

	fbr_cstore_worker_init(worker);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "process %lu", worker->thread_id);

	int ret = chttp_tcp_accept(&worker->remote_addr, &worker->server->addr);
	if (ret) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "accept() error %d", ret);
		fbr_cstore_worker_finish(worker);
		return;
	}

	chttp_addr_connected(&worker->remote_addr);
	assert_zero_dev(worker->remote_addr.error);

	char remote[128];
	int remote_port;
	chttp_sa_string(&worker->remote_addr.sa, remote, sizeof(remote), &remote_port);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "connection made %s:%d to %d",
		remote, remote_port, worker->server->port);

	fbr_cstore_proc_http(worker);

	if (worker->remote_addr.state == CHTTP_ADDR_CONNECTED) {
		// TODO keep alive on a queue somewhere
		chttp_tcp_close(&worker->remote_addr);
	}

	fbr_cstore_worker_finish(worker);
}

void
fbr_cstore_servers_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	while (cstore->servers) {
		struct fbr_cstore_server *server = cstore->servers;
		fbr_cstore_server_ok(server);

		cstore->servers = server->next;

		server->exit = 1;

		(void)shutdown(server->addr.sock, SHUT_RDWR);
		chttp_tcp_close(&server->addr);

		for (size_t i = 0; i < server->workers_max; i++) {
			pt_assert(pthread_join(server->workers[i], NULL));
		}

		assert_zero(server->workers_running);

		fbr_ZERO(server);
		free(server);
	}
}
