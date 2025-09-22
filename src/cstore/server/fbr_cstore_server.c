/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "cstore/fbr_cstore_api.h"

void
fbr_cstore_server_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_server *server = &cstore->server;

	fbr_ZERO(server);

	server->valid = 1;
}

void
fbr_cstore_server_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_server *server = &cstore->server;
	assert(server->valid);

	fbr_ZERO(server);
}
