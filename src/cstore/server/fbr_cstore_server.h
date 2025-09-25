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

struct fbr_cstore_worker {
	unsigned int				magic;
#define FBR_CSTORE_WORKER_MAGIC			0x0AC4F92D
};

struct fbr_cstore;

void fbr_cstore_server_init(struct fbr_cstore *cstore);
void fbr_cstore_server_free(struct fbr_cstore *cstore);

#endif /* _FBR_CSTORE_SERVER_H_INCLUDED_ */
