/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "fiberfs.h"
#include "chttp.h"
#include "dns/chttp_dns.h"

#include "test/fbr_test.h"

static int _SERVER_READY;

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

	client_addr->timeout_connect_ms = 500;
	client_addr->timeout_transfer_ms = 1000;

	_SERVER_READY = 1;

	int ret = chttp_tcp_accept(client_addr, server_addr);
	fbr_ASSERT(!ret && !client_addr->error, "server accept error %d", client_addr->error);

	printf("Server accepted\n");

	struct chttp_context chttp;
	chttp_context_init(&chttp);

	chttp_addr_move(&chttp.addr, client_addr);

	chttp_parse(&chttp, CHTTP_REQUEST);

	printf("chttp final state: %s\n", chttp_state_string(chttp.state));

	chttp_context_free(&chttp);

	return NULL;
}

int
main(int argc, char **argv)
{
	printf("chttp_client FUZZ %s\n", CHTTP_VERSION);

	fbr_setup_crash_signals();

	if (argc != 2) {
		printf("Usage: chttp_client [HTTP request file]\n");
		return 1;
	}

	int fd_input;

	if (!strcmp(argv[1], "_stdin")) {
		fd_input = STDIN_FILENO;
	} else {
		fd_input = open(argv[1], O_RDONLY);
	}

	fbr_ASSERT(fd_input >= 0, "Cannot get input");

	fbr_test_random_seed();

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

	addr->timeout_connect_ms = 500;
	addr->timeout_transfer_ms = 1000;

	ret = chttp_tcp_connect(addr);
	fbr_ASSERT(!ret && !addr->error, "client cannot connect to server");
	chttp_addr_connected(addr);

	printf("Client connected\n");

	char buf[1024];
	ssize_t len;
	size_t total = 0;

	do {
		size_t size = fbr_test_gen_random(1, sizeof(buf));
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

	chttp_tcp_close(addr);
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

// Test stubs
// TODO clean this up so we can use the test lib and not define these
struct fbr_test_context *
fbr_test_get_ctx(void)
{
	fbr_ABORT("no test ctx");
}

int
fbr_test_is_forked(void)
{
	fbr_ABORT("no test ctx");
}

void
fbr_test_cleanup(void)
{
	fbr_ABORT("no test ctx");
}

void
fbr_test_force_error(void)
{
	fbr_ABORT("no test ctx");
}
