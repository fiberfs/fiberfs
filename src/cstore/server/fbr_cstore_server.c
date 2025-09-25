/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_server.h"
#include "cstore/fbr_cstore_api.h"

static void *_cstore_worker_loop(void *arg);
static void _cstore_worker_process(struct fbr_cstore_worker *worker);

void
fbr_cstore_server_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_server *server = &cstore->server;

	fbr_ZERO(server);
	server->valid = 1;

	server->workers_max = _CSTORE_CONFIG.server_workers;

	for (size_t i = 0; i < server->workers_max; i++) {
		pt_assert(pthread_create(&server->workers[i], NULL, _cstore_worker_loop, cstore));
	}

	while (server->workers_running != server->workers_max) {
		fbr_sleep_ms(0.1);
	}
}

static void *
_cstore_worker_loop(void *arg)
{
	assert(arg);

	struct fbr_cstore *cstore = arg;
	fbr_cstore_ok(cstore);
	struct fbr_cstore_server *server = &cstore->server;

	struct fbr_cstore_worker *worker = fbr_cstore_worker_alloc(cstore);
	assert(worker);

	worker->thread_id = fbr_request_id_thread_gen();
	worker->thread_pos = fbr_atomic_add(&server->workers_running, 1);

	fbr_thread_name("fbr_worker");

	fbr_log_print(cstore->log, FBR_LOG_CS_WORKER, worker->thread_id, "worker %zu running",
		worker->thread_pos);

	while (!server->exit) {
		if (worker->thread_pos > server->workers_max) {
			break;
		}

		_cstore_worker_process(worker);
	}

	fbr_cstore_worker_free(worker);

	fbr_atomic_sub(&server->workers_running, 1);

	return NULL;
}

static void
_cstore_worker_process(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);

	fbr_cstore_worker_init(worker);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "process %lu", worker->thread_id);

	fbr_sleep_ms(250);

	fbr_cstore_worker_finish(worker);
}

void
fbr_cstore_server_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_server *server = &cstore->server;
	assert(server->valid);

	server->exit = 1;

	for (size_t i = 0; i < server->workers_max; i++) {
		pt_assert(pthread_join(server->workers[i], NULL));
	}

	assert_zero(server->workers_running);

	fbr_ZERO(server);
}
