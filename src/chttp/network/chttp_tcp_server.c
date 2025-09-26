/*
 * Copyright (c) 2024 chttp
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

#include "chttp.h"
#include "dns/chttp_dns.h"
#include "tls/chttp_tls.h"

void _tcp_set_timeouts(struct chttp_addr *addr);

static void
_tcp_get_port(struct chttp_addr *addr)
{
	chttp_addr_connected(addr);

	switch (addr->sa.sa_family) {
		case AF_INET:
			addr->listen_port = ntohs(addr->sa4.sin_port);
			break;
		case AF_INET6:
			addr->listen_port = ntohs(addr->sa6.sin6_port);
			break;
		default:
			fbr_ABORT("_tcp_get_port() bad sa_family");
	}

	assert(addr->listen_port > 0);
}

int
chttp_tcp_listen(struct chttp_addr *addr, const char *ip, int port, int queue_len)
{
	chttp_addr_ok(addr);
	assert(addr->sock == -1);

	int ret = chttp_dns_resolve(addr, ip, strlen(ip), port, 0);

	if (ret) {
		addr->error = CHTTP_ERR_DNS;
		return 1;
	}

	chttp_addr_resolved(addr);

	addr->sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (addr->sock < 0) {
		addr->error = CHTTP_ERR_INIT;
		return 1;
	}

	addr->state = CHTTP_ADDR_CONNECTED;
	addr->listen = 1;
	addr->resolved = 0;

	int val = 1;
	(void)setsockopt(addr->sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

	ret = bind(addr->sock, &addr->sa, addr->len);

	if (ret) {
		chttp_tcp_close(addr);
		addr->error = CHTTP_ERR_INIT;
		return 1;
	}


	ret = listen(addr->sock, queue_len);

	if (ret) {
		chttp_tcp_close(addr);
		addr->error = CHTTP_ERR_INIT;
		return 1;
	}

	chttp_addr_connected(addr);

	if (port == 0) {
		addr->len = sizeof(addr->sa6);

		(void)getsockname(addr->sock, &addr->sa, &addr->len);
	}

	_tcp_get_port(addr);

	return 0;
}

int
chttp_tcp_accept(struct chttp_addr *addr, struct chttp_addr *server_addr)
{
	chttp_addr_ok(addr);
	assert(addr->state == CHTTP_ADDR_NONE);
	assert(addr->sock == -1);
	chttp_addr_connected(server_addr);
	assert(server_addr->listen);

	chttp_addr_init(addr);

	addr->len = sizeof(addr->sa6);
	addr->sock = accept(server_addr->sock, &addr->sa, &addr->len);

	if (addr->sock < 0) {
		return 1;
	}

	addr->state = CHTTP_ADDR_CONNECTED;

	_tcp_set_timeouts(addr);

	if (server_addr->tls) {
		addr->tls = 1;

		chttp_tls_accept(addr);

		if (addr->error) {
			assert(addr->state != CHTTP_ADDR_CONNECTED);
			return 1;
		}
	}

	_tcp_get_port(addr);

	return 0;
}
