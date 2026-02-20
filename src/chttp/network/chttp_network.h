/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _CHTTP_NETWORK_H_INCLUDED_
#define _CHTTP_NETWORK_H_INCLUDED_

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "fiberfs.h"

#define CHTTP_TIMEOUT_CONNECT		3000
#define CHTTP_TIMEOUT_TRANSFER		60000

enum chttp_addr_state {
	CHTTP_ADDR_NONE = 0,
	CHTTP_ADDR_RESOLVED,
	CHTTP_ADDR_CONNECTED
};

struct chttp_addr {
	unsigned int			magic;
#define CHTTP_ADDR_MAGIC		0x8A7CEC19

	enum chttp_addr_state		state;
	int				error;

	socklen_t			len;
	int				sock;
	int				poll_result;
	short				poll_revents;
	int				listen_port;

	fbr_bitflag_t			resolved:1;
	fbr_bitflag_t			listen:1;
	fbr_bitflag_t			nonblocking:1;
	fbr_bitflag_t			reused:1;
	fbr_bitflag_t			tls:1;

	void				*tls_priv;

	double				time_start;
	int				timeout_connect_ms;
	int				timeout_transfer_ms;

	union {
		struct sockaddr		sa;
		struct sockaddr_in	sa4;
		struct sockaddr_in6	sa6;
	};
};

struct chttp_context;

void chttp_addr_init(struct chttp_addr *addr);
void chttp_addr_reset(struct chttp_addr *addr);
void chttp_addr_move(struct chttp_addr *addr_dest, struct chttp_addr *addr);
void chttp_addr_clone(struct chttp_addr *addr_dest, struct chttp_addr *addr);
int chttp_addr_cmp(const struct chttp_addr *a1, const struct chttp_addr *a2);

void chttp_tcp_set_nonblocking(struct chttp_addr *addr);
void chttp_tcp_set_blocking(struct chttp_addr *addr);
void chttp_tcp_poll(struct chttp_addr *addr, short events, int timeout_msec);
int chttp_tcp_listen(struct chttp_addr *addr, const char *ip, int port, int queue_len);
int chttp_tcp_connect(struct chttp_addr *addr);
int chttp_tcp_accept(struct chttp_addr *addr, struct chttp_addr *server_addr);
void chttp_tcp_send(struct chttp_addr *addr, const void *buf, size_t buf_len);
void chttp_tcp_read(struct chttp_context *ctx);
size_t chttp_tcp_read_ctx(struct chttp_context *ctx, void *buf, size_t buf_len);
size_t chttp_tcp_read_buf(struct chttp_addr *addr, void *buf, size_t buf_len);
void chttp_tcp_close(struct chttp_addr *addr);
void chttp_tcp_error(struct chttp_addr *addr, int error);
void chttp_tcp_error_check(struct chttp_context *ctx);

#define chttp_addr_ok(addr)					\
	fbr_magic_check(addr, CHTTP_ADDR_MAGIC)
#define chttp_addr_connected(addr)				\
{								\
	chttp_addr_ok(addr);					\
	assert((addr)->state == CHTTP_ADDR_CONNECTED);		\
	assert((addr)->sock >= 0);				\
	assert_zero((addr)->error);				\
}
#define chttp_addr_resolved(addr)				\
{								\
	chttp_addr_ok(addr);					\
	assert((addr)->state == CHTTP_ADDR_RESOLVED);		\
	assert((addr)->sock == -1);				\
}
#define chttp_addr_closed(addr)					\
{								\
	chttp_addr_ok(addr);					\
	assert((addr)->state == CHTTP_ADDR_NONE);		\
	assert((addr)->sock == -1);				\
}

#endif /* _CHTTP_NETWORK_H_INCLUDED_ */
