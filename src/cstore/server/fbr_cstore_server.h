/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_SERVER_H_INCLUDED_
#define _FBR_CSTORE_SERVER_H_INCLUDED_

#include <pthread.h>

#include "data/queue.h"
#include "network/chttp_network.h"

#define FBR_CSTORE_SERVER_ADDRESS		"127.0.0.1"
#define FBR_CSTORE_SERVER_PORT			5691
#define FBR_CSTORE_TASKS_MAX			256
#define FBR_CSTORE_WORKERS_DEFAULT		4
#define FBR_CSTORE_WORKERS_ACCEPT_DEFAULT	2

enum fbr_cstore_task_type {
	FBR_CSTORE_TASK_NONE = 0,
	FBR_CSTORE_TASK_ACCEPT
};

struct fbr_cstore_task_entry {
	unsigned int				magic;
#define FBR_CSTORE_TASK_ENTRY_MAGIC		0x825DDF00

	enum fbr_cstore_task_type		type;

	void					*param;

	TAILQ_ENTRY(fbr_cstore_task_entry)	entry;
};

struct fbr_cstore_tasks {
	struct fbr_cstore_task_entry		free_tasks[FBR_CSTORE_TASKS_MAX];

	TAILQ_HEAD(, fbr_cstore_task_entry)	task_queue;
	size_t					task_queue_len;

	pthread_mutex_t				lock;
	pthread_cond_t				cond;

	pthread_t				workers[FBR_CSTORE_TASKS_MAX];
	size_t					workers_count;
	size_t					workers_running;
	size_t					workers_idle;

	int					init;
	int					exit;
};

struct fbr_cstore_server {
	unsigned int				magic;
#define FBR_CSTORE_SERVER_MAGIC			0xAE4606E0

	struct fbr_cstore			*cstore;

	struct chttp_addr			addr;
	int					port;
	int					tls;

	struct fbr_cstore_server		*next;
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

	struct fbr_cstore_task_entry		*task;
	struct chttp_addr			remote_addr;
};

void fbr_cstore_server_alloc(struct fbr_cstore *cstore, const char *address, int port, int tls);
void fbr_cstore_server_accept(struct fbr_cstore_worker *worker);
void fbr_cstore_servers_shutdown(struct fbr_cstore *cstore);
void fbr_cstore_servers_free(struct fbr_cstore *cstore);

struct fbr_cstore_worker *fbr_cstore_worker_alloc(struct fbr_cstore *cstore);
void fbr_cstore_worker_init(struct fbr_cstore_worker *worker, struct fbr_cstore_task_entry *task);
void fbr_cstore_worker_finish(struct fbr_cstore_worker *worker);
void fbr_cstore_worker_free(struct fbr_cstore_worker *worker);

void fbr_cstore_tasks_alloc(struct fbr_cstore *cstore);
void fbr_cstore_task_add(struct fbr_cstore *cstore, enum fbr_cstore_task_type type, void *param);
void fbr_cstore_tasks_free(struct fbr_cstore *cstore);
void fbr_cstore_task_worker_add(struct fbr_cstore *cstore, size_t count);

void fbr_cstore_proc_http(struct fbr_cstore_worker *worker);

#define fbr_cstore_server_ok(server)		fbr_magic_check(server, FBR_CSTORE_SERVER_MAGIC)
#define fbr_cstore_worker_ok(worker)		fbr_magic_check(worker, FBR_CSTORE_WORKER_MAGIC)
#define fbr_cstore_task_ok(task)		fbr_magic_check(task, FBR_CSTORE_TASK_ENTRY_MAGIC)

#endif /* _FBR_CSTORE_SERVER_H_INCLUDED_ */
