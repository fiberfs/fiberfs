/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "tls/chttp_tls.h"

#include <errno.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>

void
chttp_tcp_set_nonblocking(struct chttp_addr *addr)
{
	int val, ret;

	chttp_addr_connected(addr);

	val = 1;
	ret = ioctl(addr->sock, FIONBIO, &val);
	assert_zero(ret);

	addr->nonblocking = 1;
}

void
chttp_tcp_set_blocking(struct chttp_addr *addr)
{
	int val, ret;

	chttp_addr_connected(addr);

	val = 0;
	ret = ioctl(addr->sock, FIONBIO, &val);
	assert_zero(ret);

	addr->nonblocking = 0;
}

void
chttp_tcp_poll(struct chttp_addr *addr, short events, int timeout_msec)
{
	struct pollfd fds[1];

	chttp_addr_connected(addr);
	assert(addr->nonblocking);
	assert(events);
	assert(timeout_msec > 0);

	fds[0].fd = addr->sock;
	fds[0].events = events;
	fds[0].revents = 0;

	addr->poll_result = poll(fds, 1, timeout_msec);
	addr->poll_revents = fds[0].revents;
}

static int
_tcp_poll_connected(struct chttp_addr *addr)
{
	int error, ret;
	socklen_t error_len;

	chttp_tcp_poll(addr, POLLWRNORM, addr->timeout_connect_ms);

	if (addr->poll_result <= 0) {
		return 0;
	}

	// Assume we connected
	if (addr->poll_revents & POLLWRNORM) {
		return 1;
	}

	error_len = sizeof(error);

	ret = getsockopt(addr->sock, SOL_SOCKET, SO_ERROR, &error, &error_len);
	assert_zero(ret);

	if (error) {
		return 0;
	}

	return 1;
}

void
_tcp_set_timeouts(struct chttp_addr *addr)
{
	struct timeval timeout;

	chttp_addr_connected(addr);

	addr->time_start = chttp_get_time();

	timeout.tv_sec = addr->timeout_transfer_ms / 1000;
	timeout.tv_usec = (addr->timeout_transfer_ms % 1000) * 1000;

	(void)setsockopt(addr->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout,
		sizeof(timeout));
	(void)setsockopt(addr->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout,
		sizeof(timeout));
}

int
chttp_tcp_connect(struct chttp_addr *addr)
{
	int val, ret;

	chttp_addr_resolved(addr);

	addr->sock = socket(addr->sa.sa_family, SOCK_STREAM, 0);

	if (addr->sock < 0) {
		addr->error = CHTTP_ERR_CONNECT;
		return 1;
	}

	val = 1;
	(void)setsockopt(addr->sock, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
	val = 1;
	(void)setsockopt(addr->sock, IPPROTO_TCP, TCP_FASTOPEN, &val, sizeof(val));

	addr->state = CHTTP_ADDR_CONNECTED;

	if (addr->timeout_connect_ms > 0) {
		chttp_tcp_set_nonblocking(addr);
	}

	val = connect(addr->sock, &addr->sa, addr->len);

	if (val && errno == EINPROGRESS && addr->nonblocking) {
		ret = _tcp_poll_connected(addr);

		if (ret <= 0) {
			chttp_tcp_close(addr);
			addr->error = CHTTP_ERR_CONNECT;
			return 1;
		}
	} else if (val) {
		chttp_tcp_close(addr);
		addr->error = CHTTP_ERR_CONNECT;
		return 1;
	}

	if (addr->nonblocking) {
		chttp_tcp_set_blocking(addr);
	}

	assert_zero(addr->nonblocking);

	_tcp_set_timeouts(addr);

	if (addr->tls) {
		chttp_tls_connect(addr);

		if (addr->error) {
			assert(addr->state != CHTTP_ADDR_CONNECTED);
			return 1;
		}
	}

	chttp_addr_connected(addr);

	return 0;
}

void
chttp_tcp_send(struct chttp_addr *addr, const void *buf, size_t buf_len)
{
	ssize_t ret;
	size_t written = 0;

	chttp_addr_connected(addr);
	assert_zero(addr->nonblocking);
	assert_zero(addr->listen);
	assert(buf);
	assert(buf_len);

	if (addr->tls) {
		chttp_tls_write(addr, buf, buf_len);
		return;
	}

	while (written < buf_len) {
		ret = send(addr->sock, (uint8_t*)buf + written, buf_len - written,
			MSG_NOSIGNAL);

		if (ret <= 0) {
			chttp_tcp_error(addr, CHTTP_ERR_NETWORK);
			return;
		}

		written += ret;
	}

	assert(written == buf_len);
}

void
chttp_tcp_read(struct chttp_context *ctx)
{
	size_t ret;

	chttp_context_ok(ctx);
	chttp_dpage_ok(ctx->dpage_last);
	assert(ctx->dpage_last->offset < ctx->dpage_last->length);

	ret = chttp_tcp_read_ctx(ctx, ctx->dpage_last->data + ctx->dpage_last->offset,
		ctx->dpage_last->length - ctx->dpage_last->offset);

	if (ctx->error) {
		return;
	}

	ctx->dpage_last->offset += ret;
	assert(ctx->dpage_last->offset <= ctx->dpage_last->length);
}

size_t
chttp_tcp_read_ctx(struct chttp_context *ctx, void *buf, size_t buf_len)
{
	size_t ret;

	chttp_context_ok(ctx);
	assert(buf);
	assert(buf_len);

	ret = chttp_tcp_read_buf(&ctx->addr, buf, buf_len);
	chttp_tcp_error_check(ctx);

	if (ctx->error) {
		return 0;
	} else if (ret == 0) {
		assert(ctx->addr.state != CHTTP_ADDR_CONNECTED);
		ctx->state = CHTTP_STATE_CLOSED;

		return 0;
	}

	return ret;
}

size_t
chttp_tcp_read_buf(struct chttp_addr *addr, void *buf, size_t buf_len)
{
	size_t bytes;
	ssize_t ret;

	chttp_addr_connected(addr);
	assert_zero(addr->nonblocking);
	assert_zero(addr->listen);
	assert(buf);
	assert(buf_len);

	if (addr->tls) {
		bytes = chttp_tls_read(addr, buf, buf_len);

		if (addr->error) {
			return 0;
		}

		ret = (ssize_t)bytes;
		assert(ret >= 0);
	} else {
		ret = recv(addr->sock, buf, buf_len, 0);
	}

	if (ret == 0) {
		chttp_tcp_close(addr);
		return 0;
	} else if (ret < 0) {
		chttp_tcp_error(addr, CHTTP_ERR_NETWORK);
		return 0;
	}

	return ret;
}

void
chttp_tcp_error(struct chttp_addr *addr, int error)
{
	chttp_addr_connected(addr);
	assert(error > CHTTP_ERR_NONE);

	chttp_tcp_close(addr);

	addr->error = error;
}

void
chttp_tcp_error_check(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);
	chttp_addr_ok(&ctx->addr);

	if (ctx->addr.error) {
		chttp_error(ctx, ctx->addr.error);
	}
}

void
chttp_tcp_close(struct chttp_addr *addr)
{
	chttp_addr_connected(addr);

	assert_zero(close(addr->sock));

	if (addr->resolved) {
		addr->state = CHTTP_ADDR_RESOLVED;
	} else  {
		addr->state = CHTTP_ADDR_NONE;
	}

	addr->sock = -1;

	if (addr->tls) {
		chttp_tls_close(addr);
	}
}
