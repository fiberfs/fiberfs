/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <sys/epoll.h>

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
}

// Note: must have lock
struct fbr_cstore_epool_conn *
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
	assert(conn_entry);
	fbr_object_empty(&conn_entry->addr);
	TAILQ_REMOVE(&epool->free_list, conn_entry, entry);
	TAILQ_INSERT_TAIL(&epool->free_list, conn_entry, entry);

	conn_entry->idle = 0;

	return conn_entry;
}

// Note: must have lock
void
_epool_return_conn_entry(struct fbr_cstore *cstore, struct fbr_cstore_epool_conn *conn_entry)
{
	assert_dev(cstore);
	assert_dev(conn_entry);
	assert_dev(conn_entry->addr.state == CHTTP_ADDR_NONE);
	assert_dev(conn_entry->idle);

	struct fbr_cstore_epool *epool = &cstore->epool;

	chttp_addr_reset(&conn_entry->addr);

	TAILQ_REMOVE(&epool->conn_list, conn_entry, entry);
	TAILQ_INSERT_TAIL(&epool->free_list, conn_entry, entry);
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

	pt_assert(pthread_mutex_lock(&epool->lock));

	fbr_rlog(FBR_LOG_CS_WORKER, "epool connection adding");

	struct fbr_cstore_epool_conn *conn_entry = _epool_get_conn_entry(cstore);
	assert_dev(conn_entry);

	conn_entry->idle = fbr_get_time();

	// TODO closing for now...
	chttp_tcp_close(addr);
	_epool_return_conn_entry(cstore, conn_entry);

	pt_assert(pthread_mutex_unlock(&epool->lock));
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
		assert(conn_entry);
		TAILQ_REMOVE(&epool->conn_list, conn_entry, entry);

		chttp_tcp_close(&conn_entry->addr);

		_epool_return_conn_entry(cstore, conn_entry);
	}

	while (epool->slabs) {
		struct fbr_cstore_epool_conn_slab *slab = epool->slabs;
		epool->slabs = slab->next;

		for (size_t i = 0; i < fbr_array_len(slab->conns); i++) {
			fbr_object_empty(&slab->conns[i].addr);
		}

		free(slab);
	}

	pt_assert(pthread_mutex_unlock(&epool->lock));
	pt_assert(pthread_mutex_destroy(&epool->lock));

	assert_zero(close(epool->epfd));

	fbr_zero(epool);
}
