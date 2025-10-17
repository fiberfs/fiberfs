/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <string.h>

#include "fiberfs.h"
#include "chttp.h"
#include "fbr_cstore_server.h"
#include "core/request/fbr_rlog.h"
#include "core/request/fbr_workspace.h"
#include "cstore/fbr_cstore_api.h"

static void
_http_send_code(struct chttp_context *http, int status, const char *reason)
{
	assert_dev(http);
	assert_dev(status >= 100 && status <= 999);
	assert_dev(reason);

	const char *close = "";
	if (status >= 400) {
		http->close = 1;
	}
	if (http->close) {
		close = "Connection: close\r\n";
	}

	char buffer[1024];
	size_t bytes = fbr_bprintf(buffer,
		"HTTP/1.1 %d %s\r\n"
		"Server: fiberfs cstore %s\r\n"
		"%s"
		"Content-Length: 0\r\n\r\n", status, reason, FIBERFS_VERSION, close);

	chttp_tcp_send(&http->addr, buffer, bytes);
}

void
fbr_cstore_http_log(struct chttp_context *http)
{
	chttp_context_ok(http);

	fbr_rlog(FBR_LOG_CS_WORKER,
		"state: %d error: %d ver: %d status: %d length: %ld chunk: %u gzip: %u tls: %u "
		"req: %d",
		http->state, http->error, http->version, http->status, http->length, http->chunked,
		http->gzip, http->addr.tls, http->request);

	int first = 1;
	struct chttp_dpage *dpage = http->dpage;
	while (dpage) {
		chttp_dpage_ok(dpage);

		size_t start = 0;
		for (size_t i = 0; i < dpage->length; i++) {
			if (dpage->data[i] == '\n') {
				if ((i - 1) <= start) {
					break;
				}
				if (first && http->request) {
					const char *method = (char*)dpage->data + start;
					const char *url = method + strlen(method) + 1;
					const char *version = url + strlen(url) + 1;
					fbr_rlog(FBR_LOG_CS_DEBUG, "  %s %s %s",
						method, url, version);
				} else {
					fbr_rlog(FBR_LOG_CS_DEBUG, "  %s", dpage->data + start);
				}
				first = 0;
				start = i + 1;
				continue;
			}
		}

		dpage = dpage->next;
	}
}

void
fbr_cstore_proc_http(struct fbr_cstore_task_worker *task_worker)
{
	assert(task_worker);

	struct fbr_cstore_worker *worker = task_worker->worker;
	fbr_cstore_worker_ok(worker);
	chttp_addr_connected(&task_worker->remote_addr);

	worker->time_start = fbr_get_time();

	// TODO make this a param
	size_t chttp_size = 4096;
	struct chttp_context *http = fbr_workspace_alloc(worker->workspace, chttp_size);
	if (!http) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "ERROR no workspace");
		chttp_tcp_close(&task_worker->remote_addr);
		return;
	}
	chttp_context_init_buf(http, chttp_size);
	chttp_context_ok(http);

	chttp_addr_move(&http->addr, &task_worker->remote_addr);
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

	fbr_cstore_http_log(http);

	if (http->version != CHTTP_H_VERSION_1_1) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Bad http version");
		chttp_context_free(http);
		return;
	}

	if (!strcmp(method, "GET") && http->state == CHTTP_STATE_IDLE) {
		if (!strcmp(url, "/")) {
			_http_send_code(http, 400, "Bad Request");
			chttp_context_free(http);
			return;
		}

		int ret = fbr_cstore_url_read(worker, http);
		if (ret) {
			if (ret == 1) {
				_http_send_code(http, 400, "Bad Request");
			}
			chttp_context_free(http);
			return;
		}
	} else if (!strcmp(method, "PUT") && http->state == CHTTP_STATE_BODY) {
		int ret = fbr_cstore_url_write(worker, http);
		if (ret) {
			chttp_context_free(http);
			return;
		}

		_http_send_code(http, 200, "OK");
	} else if (!strcmp(method, "DELETE") && http->state == CHTTP_STATE_IDLE) {
		int ret = fbr_cstore_url_delete(worker, http);
		if (ret < 0) {
			_http_send_code(http, 400, "Bad Request");
			chttp_context_free(http);
			return;
		} else if (ret > 0) {
			_http_send_code(http, 404, "Not found");
		} else {
			_http_send_code(http, 200, "OK");
		}
	} else if (http->state == CHTTP_STATE_IDLE) {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Bad request (400)");
		_http_send_code(http, 400, "Bad Request");
		chttp_context_free(http);
		return;
	} else {
		fbr_rdlog(worker->rlog, FBR_LOG_CS_WORKER, "Bad request (closing)");
		chttp_context_free(http);
		return;
	}

	if (http->state == CHTTP_STATE_IDLE && http->addr.state == CHTTP_ADDR_CONNECTED &&
	    !http->close) {
		chttp_addr_move(&task_worker->remote_addr, &http->addr);
	}

	// TODO, we may have some pipeline...

	chttp_context_free(http);
}
