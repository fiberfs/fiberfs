/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _CHTTP_DNS_H_INCLUDED_
#define _CHTTP_DNS_H_INCLUDED_

#include <netdb.h>
#include <stddef.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define DNS_FRESH_LOOKUP			(1 << 0)
#define DNS_DISABLE_RR				(1 << 1)

struct chttp_context;
struct chttp_addr;

void chttp_dns_lookup(struct chttp_context *ctx, const char *host, size_t host_len, int port,
	unsigned int flags);
int chttp_dns_resolve(struct chttp_addr *addr, const char *host, size_t host_len, int port,
	unsigned int flags);
void chttp_dns_copy(struct chttp_addr *addr_dest, struct sockaddr *sa, int port);
int chttp_dns_cache_lookup(const char *host, size_t host_len, struct chttp_addr *addr_dest,
	int port, unsigned int flags);
void chttp_dns_cache_store(const char *host, size_t host_len, struct addrinfo *ai_src);
extern long CHTTP_DNS_CACHE_TTL;

#endif /* _CHTTP_DNS_H_INCLUDED_ */
