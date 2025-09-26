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

// TODO fix this
extern const char *_CHTTP_HEADER_FIRST;

void
fbr_cstore_proc_http(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	chttp_addr_connected(&worker->remote_addr);

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

	// TODO move this into chttp

	http->state = CHTTP_STATE_HEADERS;
	chttp_addr_move(&http->addr, &worker->remote_addr);

	do {
		chttp_tcp_read(http);

		if (http->state >= CHTTP_STATE_CLOSED) {
			assert_dev(http->error);
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "ERROR %s",
				chttp_error_msg(http));
			chttp_context_free(http);
			return;
		}

		chttp_header_parse_request(http);

		if (http->error) {
			assert_dev(http->state >= CHTTP_STATE_CLOSED);
			fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "ERROR %s",
				chttp_error_msg(http));
			chttp_context_free(http);
			return;
		}
	} while (http->state == CHTTP_STATE_HEADERS);

	assert_zero(http->error);
	assert(http->state == CHTTP_STATE_BODY);

	// TODO 100-continue

	const char *method = chttp_header_get(http, _CHTTP_HEADER_FIRST);
	assert(method);
	size_t len = strlen(method);
	assert(len);
	const char *url = method + len + 1;

	fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "http %s request parsed url: %s",
		method, url);

	chttp_body_init(http, CHTTP_BODY_REQUEST);

	if (http->state == CHTTP_STATE_IDLE) {
		chttp_addr_move(&worker->remote_addr, &http->addr);
	} else {
		assert(http->state == CHTTP_STATE_BODY);
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "TODO request body detected");
		chttp_context_free(http);
		return;
	}

	chttp_context_free(http);
	chttp_addr_connected(&worker->remote_addr);

	// TODO temporary
	chttp_tcp_send(&worker->remote_addr, "HTTP/1.1 200 OK\r\n", 17);
	chttp_tcp_send(&worker->remote_addr, "Server: fiberfs cstore\r\n", 24);
	chttp_tcp_send(&worker->remote_addr, "Content-Length: 0\r\n\r\n", 21);
}
