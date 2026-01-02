/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_request.h"

void
fbr_cstore_epool_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_epool *epool = &cstore->epool;

	fbr_zero(epool);

	pt_assert(pthread_mutex_init(&epool->lock, NULL));

	TAILQ_INIT(&epool->conn_list);
	TAILQ_INIT(&epool->free_list);

	epool->epfd = epoll_create1(0);
        assert(epool->epfd >= 0);

	epool->timeout_sec = _CSTORE_CONFIG.keep_alive_sec;
	epool->init = 1;

	fbr_cstore_task_add(cstore, FBR_CSTORE_TASK_EPOOL, NULL);
}

// Note: must have lock
static struct fbr_cstore_epool_conn *
_epool_get_conn_entry(struct fbr_cstore *cstore)
{
	assert_dev(cstore);

	struct fbr_cstore_epool *epool = &cstore->epool;

	if (TAILQ_EMPTY(&epool->free_list)) {
		struct fbr_cstore_epool_conn_slab *slab = calloc(1, sizeof(*slab));
		assert(slab);

		for (size_t i = 0; i < fbr_array_len(slab->conns); i++) {
			TAILQ_INSERT_TAIL(&epool->free_list, &slab->conns[i], entry);
		}

		slab->next = epool->slabs;
		epool->slabs = slab;
	}

	struct fbr_cstore_epool_conn *conn_entry = TAILQ_FIRST(&epool->free_list);
	fbr_object_empty(conn_entry);
	fbr_object_empty(&conn_entry->addr);
	TAILQ_REMOVE(&epool->free_list, conn_entry, entry);
	TAILQ_INSERT_TAIL(&epool->conn_list, conn_entry, entry);

	conn_entry->magic = FBR_CSTORE_EPOOL_CONN_MAGIC;
	conn_entry->server = NULL;
	conn_entry->idle = 0;

	epool->waiting++;

	return conn_entry;
}

// Note: must have lock
static void
_epool_return_conn_entry(struct fbr_cstore *cstore, struct fbr_cstore_epool_conn *conn_entry,
    struct chttp_addr *move_addr)
{
	assert_dev(cstore);
	fbr_cstore_epool_conn_ok(conn_entry);
	chttp_addr_connected(&conn_entry->addr);
	assert_dev(conn_entry->server);
	assert_dev(conn_entry->idle);

	struct fbr_cstore_epool *epool = &cstore->epool;

	int ret = epoll_ctl(epool->epfd, EPOLL_CTL_DEL, conn_entry->addr.sock, NULL);
	fbr_ASSERT(ret == 0, "epoll_ctl failed %d %d", ret, errno);

	if (move_addr) {
		chttp_addr_move(move_addr, &conn_entry->addr);
		chttp_addr_connected(move_addr);
	} else {
		chttp_tcp_close(&conn_entry->addr);
	}

	assert_dev(conn_entry->addr.state == CHTTP_ADDR_NONE);
	chttp_addr_reset(&conn_entry->addr);

	TAILQ_REMOVE(&epool->conn_list, conn_entry, entry);
	TAILQ_INSERT_TAIL(&epool->free_list, conn_entry, entry);

	epool->waiting--;
}

void
fbr_cstore_epool_add(struct fbr_cstore_server *server, struct chttp_addr *addr)
{
	fbr_cstore_server_ok(server);
	chttp_addr_connected(addr);

	struct fbr_cstore *cstore = server->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_epool *epool = &cstore->epool;
	assert(epool->init);

	if (epool->debug_close) {
		chttp_tcp_close(addr);
		return;
	}

	pt_assert(pthread_mutex_lock(&epool->lock));

	fbr_rlog(FBR_LOG_CS_WORKER, "epool connection adding");

	struct fbr_cstore_epool_conn *conn_entry = _epool_get_conn_entry(cstore);
	fbr_cstore_epool_conn_ok(conn_entry);

	conn_entry->server = server;
	conn_entry->idle = fbr_get_time();
	chttp_addr_move(&conn_entry->addr, addr);
	chttp_addr_connected(&conn_entry->addr);

	struct epoll_event event;
	fbr_zero(&event);
	event.events = EPOLLIN | EPOLLRDHUP;
	event.data.ptr = conn_entry;

	int ret = epoll_ctl(epool->epfd, EPOLL_CTL_ADD, conn_entry->addr.sock, &event);
	assert_zero(ret);

	pt_assert(pthread_mutex_unlock(&epool->lock));
}

void
fbr_cstore_epool_proc(struct fbr_cstore_task_worker *task_worker)
{
	assert(task_worker);

	struct fbr_cstore_worker *worker = task_worker->worker;
	fbr_cstore_worker_ok(worker);
	fbr_cstore_task_ok(task_worker->task);
	assert_zero(task_worker->task->param);
	assert(task_worker->remote_addr.state == CHTTP_ADDR_NONE);

	struct fbr_cstore *cstore = worker->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_epool *epool = &cstore->epool;
	assert(epool->init);

	fbr_rlog(FBR_LOG_CS_WORKER, "epool entering processing");

	assert_zero(epool->in_wait);
	epool->in_wait = 1;

	struct fbr_cstore_epool_conn *conn_entry = NULL;
	struct epoll_event event;
	int event_count = 0;

	while (!epool->exit) {
		double now = fbr_get_time();

		pt_assert(pthread_mutex_lock(&epool->lock));

		while (!TAILQ_EMPTY(&epool->conn_list)) {
			struct fbr_cstore_epool_conn *conn_entry = TAILQ_FIRST(&epool->conn_list);
			fbr_cstore_epool_conn_ok(conn_entry);
			assert_dev(conn_entry->idle);

			if (conn_entry->idle + epool->timeout_sec < now) {
				_epool_return_conn_entry(cstore, conn_entry, NULL);
			} else {
				break;
			}
		}

		pt_assert(pthread_mutex_unlock(&epool->lock));

		// TODO schedule the timeout better, also include a breakout signal
		event_count = epoll_wait(epool->epfd, &event, 1, 250);
		assert(event_count >= 0 || errno == EINTR);
		assert(event_count <= 1);

		pt_assert(pthread_mutex_lock(&epool->lock));

		if (event_count <= 0 || epool->exit) {
			pt_assert(pthread_mutex_unlock(&epool->lock));
			continue;
		}

		conn_entry = event.data.ptr;
		fbr_cstore_epool_conn_ok(conn_entry);
		fbr_cstore_server_ok(conn_entry->server);

		int bytes;
		int ret = ioctl(conn_entry->addr.sock, FIONREAD, &bytes);
		if (ret < 0) {
			bytes = 0;
		}

		fbr_rlog(FBR_LOG_CS_WORKER, "epool wait: %d bytes: %d", event.events, bytes);

		if (event.events & EPOLLIN && bytes > 0) {
			task_worker->task->param = conn_entry->server;
			_epool_return_conn_entry(cstore, conn_entry, &task_worker->remote_addr);

			pt_assert(pthread_mutex_unlock(&epool->lock));

			break;
		} else {
			_epool_return_conn_entry(cstore, conn_entry, NULL);
		}

		pt_assert(pthread_mutex_unlock(&epool->lock));
	}

	epool->in_wait = 0;

	if (epool->exit) {
		if (task_worker->remote_addr.state == CHTTP_ADDR_CONNECTED) {
			chttp_tcp_close(&task_worker->remote_addr);
		}
		return;
	}

	fbr_cstore_task_add(cstore, FBR_CSTORE_TASK_EPOOL, NULL);

	fbr_cstore_server_proc(task_worker, 0);
}

void
fbr_cstore_epool_shutdown(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	cstore->epool.exit = 1;

	// TODO trigger a signal to break out of epoll
}

void
fbr_cstore_epool_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_epool *epool = &cstore->epool;
	if (!epool->init) {
		return;
	}

	assert(epool->exit);

	pt_assert(pthread_mutex_lock(&epool->lock));

	while (!TAILQ_EMPTY(&epool->conn_list)) {
		struct fbr_cstore_epool_conn *conn_entry = TAILQ_FIRST(&epool->conn_list);
		fbr_cstore_epool_conn_ok(conn_entry);

		_epool_return_conn_entry(cstore, conn_entry, NULL);
	}

	while (epool->slabs) {
		struct fbr_cstore_epool_conn_slab *slab = epool->slabs;
		epool->slabs = slab->next;

		for (size_t i = 0; i < fbr_array_len(slab->conns); i++) {
			fbr_object_empty(&slab->conns[i].addr);
			TAILQ_REMOVE(&epool->free_list, &slab->conns[i], entry);
		}

		free(slab);
	}

	assert(TAILQ_EMPTY(&epool->free_list));
	assert_zero(epool->waiting);

	pt_assert(pthread_mutex_unlock(&epool->lock));
	pt_assert(pthread_mutex_destroy(&epool->lock));

	assert_zero(close(epool->epfd));

	fbr_zero(epool);
}
