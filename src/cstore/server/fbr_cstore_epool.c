/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "chttp.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_request.h"

void
fbr_cstore_epool_add(struct fbr_cstore_server *server, struct chttp_addr *addr)
{
	fbr_cstore_server_ok(server);
	chttp_addr_connected(addr);

	fbr_rlog(FBR_LOG_CS_WORKER, "epool connection found...");

	// TODO closing for now...
	chttp_tcp_close(addr);
}
