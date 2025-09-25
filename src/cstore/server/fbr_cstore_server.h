/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_SERVER_H_INCLUDED_
#define _FBR_CSTORE_SERVER_H_INCLUDED_

#include <pthread.h>

#define FBR_CSTORE_WORKER_MAX			256
#define FBR_CSTORE_WORKER_DEFAULT		4

struct fbr_cstore_server {
	int					valid;
	volatile int				exit;

	int					port;

	pthread_t				workers[FBR_CSTORE_WORKER_MAX];
	size_t					workers_max;
	size_t					workers_running;
};

struct fbr_cstore;

struct fbr_cstore_worker {
	unsigned int				magic;
#define FBR_CSTORE_WORKER_MAGIC			0x0AC4F92D

	struct fbr_cstore			*cstore;
	struct fbr_workspace			*workspace;
	struct fbr_rlog				*rlog;

	unsigned long				thread_id;
	unsigned long				thread_pos;

	double					time_start;
	unsigned long				request_id;
};

void fbr_cstore_server_init(struct fbr_cstore *cstore);
void fbr_cstore_server_free(struct fbr_cstore *cstore);

struct fbr_cstore_worker *fbr_cstore_worker_alloc(struct fbr_cstore *cstore);
void fbr_cstore_worker_init(struct fbr_cstore_worker *worker);
void fbr_cstore_worker_finish(struct fbr_cstore_worker *worker);
void fbr_cstore_worker_free(struct fbr_cstore_worker *worker);

#define fbr_cstore_worker_ok(worker)		\
	fbr_magic_check(worker, FBR_CSTORE_WORKER_MAGIC)

#endif /* _FBR_CSTORE_SERVER_H_INCLUDED_ */
