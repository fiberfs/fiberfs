/*
 * Copyright (c) 2021-2026 FiberFS LLC
 *
 */

#include "chttp.h"
#include "tls/chttp_tls.h"

void
chttp_addr_init(struct chttp_addr *addr)
{
	chttp_addr_reset(addr);

	addr->magic = CHTTP_ADDR_MAGIC;
	addr->sock = -1;

	addr->timeout_connect_ms = CHTTP_TIMEOUT_CONNECT;
	addr->timeout_transfer_ms = CHTTP_TIMEOUT_TRANSFER;

	chttp_addr_closed(addr);
}

void
chttp_addr_reset(struct chttp_addr *addr)
{
	fbr_zero(addr);
}

void
chttp_addr_move(struct chttp_addr *addr_dest, struct chttp_addr *addr)
{
	chttp_addr_ok(addr);

	chttp_addr_clone(addr_dest, addr);

	addr->error = 0;
	addr->sock = -1;
	addr->listen = 0;
	addr->nonblocking = 0;
	addr->reused = 0;
	addr->tls = 0;
	addr->tls_priv = NULL;

	if (addr->resolved) {
		addr->state = CHTTP_ADDR_RESOLVED;
		chttp_addr_resolved(addr);
	} else {
		addr->state = CHTTP_ADDR_NONE;
	}
}

void
chttp_addr_clone(struct chttp_addr *addr_dest, struct chttp_addr *addr)
{
	chttp_addr_ok(addr);

	memcpy(addr_dest, addr, sizeof(*addr_dest));

	chttp_addr_ok(addr_dest);
}

int
chttp_addr_cmp(const struct chttp_addr *a1, const struct chttp_addr *a2)
{
	chttp_addr_ok(a1);
	chttp_addr_ok(a2);

	if (a1->len != a2->len) {
		return a2->len - a1->len;
	}

	if (a1->tls != a2->tls) {
		return a2->tls - a1->tls;
	}

	return memcmp(&a1->sa, &a2->sa, a1->len);
}
