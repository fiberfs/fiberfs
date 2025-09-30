/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <string.h>

#include "fiberfs.h"
#include "chttp.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_rlog.h"
#include "core/request/fbr_workspace.h"
#include "cstore/fbr_cstore_api.h"

void
_http_send_400(struct chttp_context *http)
{
	assert_dev(http);
	static_ASSERT(sizeof(FIBERFS_VERSION) == 6);

	chttp_tcp_send(&http->addr,
		"HTTP/1.1 400 Bad Request\r\n"
		"Server: fiberfs cstore " FIBERFS_VERSION "\r\n"
		"Content-Length: 0\r\n"
		"Connection: close\r\n\r\n", 96);
}

void
fbr_cstore_proc_http(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	chttp_addr_connected(&worker->remote_addr);

	worker->time_start = fbr_get_time();

	// TODO make this a param
	size_t chttp_size = 4096;
	struct chttp_context *http = fbr_workspace_alloc(worker->workspace, chttp_size);
	if (!http) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "ERROR no workspace");
		chttp_tcp_close(&worker->remote_addr);
		return;
	}
	chttp_context_init_buf(http, chttp_size);
	chttp_context_ok(http);

	chttp_addr_move(&http->addr, &worker->remote_addr);
	chttp_parse(http, CHTTP_REQUEST);

	if (http->error) {
		assert_dev(http->state >= CHTTP_STATE_CLOSED);
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "ERROR %s",
			chttp_error_msg(http));
		chttp_context_free(http);
		return;
	}

	const char *method = chttp_header_get_method(http);
	const char *url = chttp_header_get_url(http);

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "http %s url: %s", method, url);

	if (http->version != CHTTP_H_VERSION_1_1) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Bad http version");
		chttp_context_free(http);
		return;
	}

	if (!strcmp(method, "GET") && http->state == CHTTP_STATE_IDLE) {
		if (!strcmp(url, "/")) {
			_http_send_400(http);
			chttp_context_free(http);
			return;
		}

		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Get (TODO)");
	} else if (!strcmp(method, "PUT") && http->state == CHTTP_STATE_BODY) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Insert (TODO)");
	} else if (http->state == CHTTP_STATE_IDLE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Bad request (400)");
		_http_send_400(http);
		chttp_context_free(http);
		return;
	} else {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Bad request (closing)");
		chttp_context_free(http);
		return;
	}

	if (http->addr.state == CHTTP_ADDR_CONNECTED && !http->close) {
		chttp_addr_move(&worker->remote_addr, &http->addr);
	}

	chttp_context_free(http);
}
