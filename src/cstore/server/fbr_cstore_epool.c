/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

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

	fbr_zero(&cstore->epool);

	pt_assert(pthread_mutex_init(&cstore->epool.lock, NULL));

	cstore->epool.epfd = epoll_create1(0);
        assert(cstore->epool.epfd >= 0);

	cstore->epool.timeout_sec = _CSTORE_CONFIG.keep_alive_sec;
	cstore->epool.init = 1;
}

void
fbr_cstore_epool_add(struct fbr_cstore_server *server, struct chttp_addr *addr)
{
	fbr_cstore_server_ok(server);
	chttp_addr_connected(addr);

	struct fbr_cstore *cstore = server->cstore;
	fbr_cstore_ok(cstore);
	assert(cstore->epool.init);

	fbr_rlog(FBR_LOG_CS_WORKER, "epool connection found...");

	// TODO closing for now...
	chttp_tcp_close(addr);
}

void
fbr_cstore_epool_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	if (!cstore->epool.init) {
		return;
	}

	pt_assert(pthread_mutex_destroy(&cstore->epool.lock));

	assert_zero(close(cstore->epool.epfd));

	fbr_zero(&cstore->epool);
}
