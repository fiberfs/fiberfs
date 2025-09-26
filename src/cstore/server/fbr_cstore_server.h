/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_SERVER_H_INCLUDED_
#define _FBR_CSTORE_SERVER_H_INCLUDED_

#include <pthread.h>

#include "network/chttp_network.h"

#define FBR_CSTORE_SERVER_PORT			5691
#define FBR_CSTORE_SERVER_LISTEN		"127.0.0.1"
#define FBR_CSTORE_WORKER_MAX			256
#define FBR_CSTORE_WORKER_DEFAULT		4

struct fbr_cstore_server {
	unsigned int				magic;
#define FBR_CSTORE_SERVER_MAGIC			0xAE4606E0

	volatile int				exit;

	struct fbr_cstore			*cstore;

	struct chttp_addr			addr;
	int					port;
	int					tls;

	pthread_t				workers[FBR_CSTORE_WORKER_MAX];
	size_t					workers_max;
	size_t					workers_running;

	struct fbr_cstore_server		*next;
};

struct fbr_cstore;

struct fbr_cstore_worker {
	unsigned int				magic;
#define FBR_CSTORE_WORKER_MAGIC			0x0AC4F92D

	struct fbr_cstore_server		*server;
	struct fbr_workspace			*workspace;
	struct fbr_rlog				*rlog;

	unsigned long				thread_id;
	unsigned long				thread_pos;

	double					time_start;
	unsigned long				request_id;

	struct chttp_addr			remote_addr;
};

void fbr_cstore_server_alloc(struct fbr_cstore *cstore, const char *address, int port, int tls);
void fbr_cstore_servers_free(struct fbr_cstore *cstore);

struct fbr_cstore_worker *fbr_cstore_worker_alloc(struct fbr_cstore_server *server);
void fbr_cstore_worker_init(struct fbr_cstore_worker *worker);
void fbr_cstore_worker_finish(struct fbr_cstore_worker *worker);
void fbr_cstore_worker_free(struct fbr_cstore_worker *worker);

#define fbr_cstore_server_ok(server)		fbr_magic_check(server, FBR_CSTORE_SERVER_MAGIC)
#define fbr_cstore_worker_ok(worker)		fbr_magic_check(worker, FBR_CSTORE_WORKER_MAGIC)

#endif /* _FBR_CSTORE_SERVER_H_INCLUDED_ */
