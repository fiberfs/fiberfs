/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

struct fbr_cstore_worker *
fbr_cstore_worker_alloc(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	size_t workspace_size = fbr_workspace_size();
	struct fbr_cstore_worker *worker = calloc(1, sizeof(*worker) + workspace_size);
	assert(worker);

	worker->magic = FBR_CSTORE_WORKER_MAGIC;
	worker->workspace = fbr_workspace_init(worker + 1, workspace_size);
	worker->cstore = cstore;

	return worker;
}

void
fbr_cstore_worker_init(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_workspace_ok(worker->workspace);
	assert_dev(worker->workspace->free >= FBR_WORKSPACE_MIN_SIZE);
	assert_zero_dev(worker->workspace->pos);
	assert_zero(worker->request_id);

	worker->time_start = fbr_get_time();
	worker->request_id = fbr_request_id_gen();

	fbr_wlog_workspace_alloc(worker);
}

void
fbr_cstore_worker_finish(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	assert_dev(worker->request_id);

	worker->time_start = 0;
	worker->request_id = 0;

	fbr_rlog_free(&worker->rlog);
	fbr_workspace_reset(worker->workspace);
}

void
fbr_cstore_worker_free(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);

	fbr_workspace_free(worker->workspace);

	fbr_zero(worker);
	free(worker);
}
