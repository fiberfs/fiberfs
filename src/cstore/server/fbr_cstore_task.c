/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"

void
fbr_cstore_tasks_alloc(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_tasks *tasks = &cstore->tasks;
	fbr_zero(tasks);

	TAILQ_INIT(&tasks->task_queue);
	pt_assert(pthread_mutex_init(&tasks->lock, NULL));
	pt_assert(pthread_cond_init(&tasks->cond, NULL));

	fbr_cstore_worker_key_init();

	tasks->init = 1;
}

// Note: tasks->lock required
static struct fbr_cstore_task_entry *
_cstore_task_alloc(struct fbr_cstore_tasks *tasks)
{
	assert_dev(tasks);

	for (size_t i = 0; i < fbr_array_len(tasks->free_tasks); i++) {
		struct fbr_cstore_task_entry *task = &tasks->free_tasks[i];
		if (fbr_object_is_empty(task)) {
			assert_zero_dev(task->type);
			task->magic = FBR_CSTORE_TASK_ENTRY_MAGIC;
			return task;
		}
	}

	return NULL;
}

void
fbr_cstore_task_add(struct fbr_cstore *cstore, enum fbr_cstore_task_type type, void *param)
{
	fbr_cstore_ok(cstore);
	assert(type);

	struct fbr_cstore_tasks *tasks = &cstore->tasks;
	assert(tasks->init);

	if (tasks->exit) {
		return;
	}

	pt_assert(pthread_mutex_lock(&tasks->lock));

	struct fbr_cstore_task_entry *task = _cstore_task_alloc(tasks);
	fbr_cstore_task_ok(task);

	task->type = type;
	task->param = param;

	// TODO priority

	TAILQ_INSERT_TAIL(&tasks->task_queue, task, entry);
	tasks->task_queue_len++;

	pt_assert(pthread_cond_signal(&tasks->cond));

	pt_assert(pthread_mutex_unlock(&tasks->lock));
}

// Note: tasks->lock required
static void
_cstore_task_free(struct fbr_cstore_task_worker *task_worker)
{
	assert_dev(task_worker);
	fbr_cstore_worker_ok(task_worker->worker);
	fbr_cstore_task_ok(task_worker->task);
	assert(task_worker->remote_addr.state == CHTTP_ADDR_NONE);

	fbr_zero(task_worker->task);
	task_worker->task = NULL;
}

static void *
_cstore_task_loop(void *arg)
{
	assert(arg);

	struct fbr_cstore *cstore = arg;
	fbr_cstore_ok(cstore);
	fbr_log_ok(cstore->log);
	struct fbr_cstore_tasks *tasks = &cstore->tasks;

	struct fbr_cstore_task_worker task_worker;
	fbr_zero(&task_worker);

	task_worker.worker = fbr_cstore_worker_alloc(cstore, "server_task");
	fbr_cstore_worker_ok(task_worker.worker);

	chttp_addr_init(&task_worker.remote_addr);

	task_worker.worker->thread_id = fbr_request_id_thread_gen();
	task_worker.worker->thread_pos = fbr_atomic_add(&tasks->workers_running, 1);

	fbr_thread_name("fbr_task");

	pt_assert(pthread_mutex_lock(&tasks->lock));

	while (!tasks->exit) {
		if (!tasks->task_queue_len) {
			assert_dev(TAILQ_EMPTY(&tasks->task_queue));
			tasks->workers_idle++;

			pt_assert(pthread_cond_wait(&tasks->cond, &tasks->lock));

			tasks->workers_idle--;

			continue;
		}

		struct fbr_cstore_task_entry *task = TAILQ_FIRST(&tasks->task_queue);
		fbr_cstore_task_ok(task);

		TAILQ_REMOVE(&tasks->task_queue, task, entry);
		tasks->task_queue_len--;

		pt_assert(pthread_mutex_unlock(&tasks->lock));

		fbr_cstore_worker_init(task_worker.worker, NULL);
		task_worker.task = task;

		switch(task->type) {
			case FBR_CSTORE_TASK_ACCEPT:
				fbr_cstore_server_accept(&task_worker);
				break;
			case FBR_CSTORE_TASK_EPOOL:
				fbr_cstore_epool_proc(&task_worker);
				break;
			default:
				fbr_ABORT("bad task type: %d", task->type);
		}

		fbr_cstore_worker_finish(task_worker.worker);

		pt_assert(pthread_mutex_lock(&tasks->lock));

		_cstore_task_free(&task_worker);
	}

	pt_assert(pthread_mutex_unlock(&tasks->lock));

	fbr_cstore_worker_free(task_worker.worker);

	assert_zero_dev(task_worker.task);
	assert_dev(task_worker.remote_addr.state == CHTTP_ADDR_NONE);
	fbr_zero(&task_worker);

	fbr_atomic_sub(&tasks->workers_running, 1);

	return NULL;
}

void
fbr_cstore_task_worker_add(struct fbr_cstore *cstore, size_t count)
{
	fbr_cstore_ok(cstore);
	assert(count);

	struct fbr_cstore_tasks *tasks = &cstore->tasks;
	assert(tasks->init);

	tasks->workers_count += count;
	assert(tasks->workers_count <= FBR_CSTORE_TASKS_MAX);

	for (size_t i = 0; i < count; i++) {
		pt_assert(pthread_create(&tasks->workers[i], NULL, _cstore_task_loop, cstore));
	}

	while (tasks->workers_running != tasks->workers_count) {
		assert_dev(tasks->workers_running <= tasks->workers_count);
		fbr_sleep_ms(0.1);
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_WORKER, FBR_REQID_CSTORE, "workers added: %zu",
		count);
}

void
fbr_cstore_tasks_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_tasks *tasks = &cstore->tasks;

	if (!tasks->init) {
		return;
	}

	tasks->exit = 1;

	fbr_cstore_epool_shutdown(cstore);
	fbr_cstore_servers_shutdown(cstore);

	pt_assert(pthread_mutex_lock(&tasks->lock));
	pt_assert(pthread_cond_broadcast(&tasks->cond));
	pt_assert(pthread_mutex_unlock(&tasks->lock));

	for (size_t i = 0; i < tasks->workers_count; i++) {
		pt_assert(pthread_join(tasks->workers[i], NULL));
	}

	assert_zero(tasks->workers_running);

	pt_assert(pthread_mutex_destroy(&tasks->lock));
	pt_assert(pthread_cond_destroy(&tasks->cond));

	fbr_cstore_worker_key_free();

	fbr_zero(tasks);
}
