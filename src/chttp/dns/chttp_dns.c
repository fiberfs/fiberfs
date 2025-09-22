/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "dns/chttp_dns.h"

void
chttp_dns_copy(struct chttp_addr *addr_dest, struct sockaddr *sa, int port)
{
	assert(addr_dest);
	assert(sa);
	assert(port >= 0 && port <= UINT16_MAX);

	chttp_addr_init(addr_dest);

	switch (sa->sa_family) {
		case AF_INET:
			addr_dest->len = sizeof(struct sockaddr_in);
			break;
		case AF_INET6:
			addr_dest->len = sizeof(struct sockaddr_in6);
			break;
		default:
			return;
	}

	memcpy(&addr_dest->sa, sa, addr_dest->len);

	switch (addr_dest->sa.sa_family) {
		case AF_INET:
			addr_dest->sa4.sin_port = htons(port);
			break;
		case AF_INET6:
			addr_dest->sa6.sin6_port = htons(port);
			break;
		default:
			fbr_ABORT("Incorrect address type");
	}

	addr_dest->state = CHTTP_ADDR_RESOLVED;
	addr_dest->resolved = 1;
}

int
chttp_dns_resolve(struct chttp_addr *addr, const char *host, size_t host_len, int port,
    unsigned int flags)
{
	assert(addr);
	assert(host);
	assert(host_len);
	assert(port >= 0 && port <= UINT16_MAX);

	chttp_addr_reset(addr);

	if (!(flags & DNS_FRESH_LOOKUP)) {
		int ret = chttp_dns_cache_lookup(host, host_len, addr, port, flags);

		if (ret) {
			chttp_addr_resolved(addr);
			return 0;
		}
	}

	struct addrinfo hints;
	fbr_ZERO(&hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	struct addrinfo *ai_res_list;
	int ret = getaddrinfo(host, NULL, &hints, &ai_res_list);

	if (ret) {
		return 1;
	}

	// Always use the first address entry on a fresh lookup
	chttp_dns_copy(addr, ai_res_list->ai_addr, port);

	if (addr->state == CHTTP_ADDR_NONE) {
		freeaddrinfo(ai_res_list);
		return 1;
	}

	chttp_dns_cache_store(host, host_len, ai_res_list);

	freeaddrinfo(ai_res_list);

	chttp_addr_resolved(addr);

	return 0;
}

void
chttp_dns_lookup(struct chttp_context *ctx, const char *host, size_t host_len, int port,
    unsigned int flags)
{
	chttp_context_ok(ctx);

	int ret = chttp_dns_resolve(&ctx->addr, host, host_len, port, flags);
	if (ret) {
		chttp_error(ctx, CHTTP_ERR_DNS);
		return;
	}
}
