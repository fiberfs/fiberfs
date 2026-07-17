/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "chttp.h"
#include "dns/chttp_dns.h"

static int _SERVER_READY;

static void
_random_seed(void)
{
	struct timespec now;
	assert_zero(clock_gettime(CLOCK_MONOTONIC, &now));

	srandom(now.tv_sec + now.tv_nsec);
}

// Inclusive
static long
_gen_random(long low, long high)
{
	assert(low >= 0);
	assert(high >= low);

	long rval = random();
	rval %= (high - low) + 1;
	rval += low;

	return rval;
}

static void *
_server_thread(void *arg)
{
	struct chttp_addr *server_addr = arg;
	chttp_addr_connected(server_addr);
	assert_zero(_SERVER_READY);

	printf("Server started\n");

	struct chttp_addr _client_addr;
	struct chttp_addr *client_addr = &_client_addr;
	chttp_addr_init(client_addr);
	chttp_addr_closed(client_addr);

	client_addr->timeout_connect_ms = 100;
	client_addr->timeout_transfer_ms = 100;

	_SERVER_READY = 1;

	int ret = chttp_tcp_accept(client_addr, server_addr);
	fbr_ASSERT(!ret && !client_addr->error, "server accept error %d", client_addr->error);

	printf("Server accepted\n");

	struct chttp_context chttp;
	chttp_context_init(&chttp);

	chttp_addr_move(&chttp.addr, client_addr);

	chttp_parse(&chttp, CHTTP_REQUEST);

	if (chttp.state >= CHTTP_STATE_BODY && chttp.state <= CHTTP_STATE_IDLE) {
		const char *method = chttp_header_get_method(&chttp);
		assert(method);

		printf("  chttp final state: %s (%s)\n", chttp_state_string(chttp.state), method);
	} else {
		printf("  chttp final state: %s\n", chttp_state_string(chttp.state));
	}

	chttp_context_free(&chttp);

	return NULL;
}

int
main(int argc, char **argv)
{
	printf("chttp_fuzz %s\n", CHTTP_VERSION);

	fbr_setup_crash_signals();
	fbr_allow_abort();

	if (argc != 2) {
		printf("Usage: chttp_fuzz [HTTP request file]\n");
		return 1;
	}

	int fd_input;

	if (!strcmp(argv[1], "_stdin")) {
		fd_input = STDIN_FILENO;
	} else {
		fd_input = open(argv[1], O_RDONLY);
	}

	fbr_ASSERT(fd_input >= 0, "Cannot get input");

	_random_seed();

	struct chttp_addr _server_addr;
	struct chttp_addr *server_addr = &_server_addr;
	chttp_addr_init(server_addr);
	chttp_addr_closed(server_addr);

	int ret = chttp_tcp_listen(server_addr, "127.0.0.1", 0, 0);
	fbr_ASSERT(!ret && !server_addr->error, "server listen failed");
	chttp_addr_connected(server_addr);

	printf("Server port: %d\n", server_addr->listen_port);

	pthread_t server_thread;
	pt_assert(pthread_create(&server_thread, NULL, _server_thread, server_addr));

	while (!_SERVER_READY) {
		fbr_sleep_ms(0.001);
	}

	struct chttp_addr _addr;
	struct chttp_addr *addr = &_addr;

	ret = chttp_dns_resolve(addr, "127.0.0.1", 9, server_addr->listen_port, DNS_FRESH_LOOKUP);
	fbr_ASSERT(!ret, "client cant resolve server");
	chttp_addr_resolved(addr);

	addr->timeout_connect_ms = 100;
	addr->timeout_transfer_ms = 1000;

	ret = chttp_tcp_connect(addr);
	fbr_ASSERT(!ret && !addr->error, "client cannot connect to server");
	chttp_addr_connected(addr);

	printf("Client connected\n");

	char buf[1024];
	ssize_t len;
	size_t total = 0;

	do {
		size_t size = _gen_random(1, sizeof(buf));
		len = read(fd_input, buf, size);
		assert(len >= 0);

		if (!len) {
			break;
		}

		chttp_tcp_send(addr, buf, len);
		if (addr->error) {
			printf("Client send error\n");
			break;
		}

		total += len;
	} while (len > 0);

	assert_zero(close(fd_input));

	pt_assert(pthread_join(server_thread, NULL));

	printf("Server done\n");

	if (addr->state == CHTTP_ADDR_CONNECTED) {
		chttp_tcp_close(addr);
	}
	chttp_addr_resolved(addr);

	printf("Client sent %zu bytes\n", total);

	chttp_tcp_close(server_addr);
	chttp_addr_closed(server_addr);

	return 0;
}

// Required for fiber asserting
void
fbr_context_abort(int pre_abort)
{
	(void)pre_abort;
}
