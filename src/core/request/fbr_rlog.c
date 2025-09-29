/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
#include <stdio.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "core/fuse/fbr_fuse.h"
#include "cstore/fbr_cstore_api.h"
#include "cstore/server/fbr_cstore_server.h"
#include "log/fbr_log.h"

static void
_rlog_init(struct fbr_rlog *rlog, size_t rlog_size, unsigned long request_id)
{
	assert_dev(rlog);
	assert(rlog_size > sizeof(*rlog));
	assert(rlog_size < FBR_LOG_SEGMENT_MIN_SIZE); // TODO
	assert(rlog_size <= USHRT_MAX);

	fbr_ZERO(rlog);

	rlog->magic = FBR_RLOG_MAGIC;
	rlog->request_id = request_id;
	rlog->log_end = rlog->data + ((rlog_size - sizeof(*rlog)) / FBR_LOG_TYPE_SIZE);
	rlog->log_pos = rlog->data;
	assert(rlog->log_pos < rlog->log_end);
}

void
fbr_rlog_workspace_alloc(struct fbr_request *request)
{
	fbr_request_ok(request);
	fbr_fuse_context_ok(request->fuse_ctx);
	assert_dev(request->id);
	assert_zero(request->rlog);

	// TODO pull this from fs->config
	size_t rlog_size = FBR_RLOG_MIN_SIZE;

	request->rlog = fbr_workspace_alloc(request->workspace, rlog_size);
	assert(request->rlog);

	_rlog_init(request->rlog, rlog_size, request->id);
	fbr_rlog_ok(request->rlog);

	request->rlog->log = request->fuse_ctx->log;
	fbr_log_ok(request->rlog->log);
}

void
fbr_wlog_workspace_alloc(struct fbr_cstore_worker *worker)
{
	fbr_cstore_worker_ok(worker);
	fbr_cstore_ok(worker->cstore);
	assert_dev(worker->request_id);
	assert_zero(worker->rlog);

	// TODO see above
	size_t rlog_size = FBR_RLOG_MIN_SIZE;

	worker->rlog = fbr_workspace_alloc(worker->workspace, rlog_size);
	assert(worker->rlog);

	_rlog_init(worker->rlog, rlog_size, worker->request_id);
	fbr_rlog_ok(worker->rlog);

	worker->rlog->log = worker->cstore->log;
	fbr_log_ok(worker->rlog->log);
}

void
fbr_rlog_flush(struct fbr_rlog *rlog)
{
	fbr_rlog_ok(rlog);
	fbr_log_ok(rlog->log);

	if (!rlog->lines) {
		assert_dev(rlog->log_pos == rlog->data);
		return;
	}

	assert(rlog->log_pos > rlog->data);
	size_t length = (rlog->log_pos - rlog->data) * FBR_LOG_TYPE_SIZE;

	fbr_log_batch(rlog->log, rlog->data, length, rlog->lines);

	rlog->log_pos = rlog->data;
	rlog->lines = 0;
}

static inline size_t
_rlog_space(struct fbr_rlog *rlog)
{
	assert_dev(rlog);
	return (rlog->log_end - rlog->log_pos) * FBR_LOG_TYPE_SIZE;
}

static void
_rlog_log(struct fbr_rlog *rlog, enum fbr_log_type type, const char *fmt, va_list ap)
{
	assert_dev(rlog);
	assert_dev(rlog->log);
	assert(rlog->log_pos <= rlog->log_end);
	assert_dev(rlog->request_id);
	assert_dev(type);
	assert_dev(fmt);

	size_t space = _rlog_space(rlog);
	fbr_log_data_t *tag = NULL;
	size_t length;
	int retry = 1;

	while (1) {
		if (space < 128) {
			fbr_rlog_flush(rlog);
			space = _rlog_space(rlog);
			assert_dev(space > 128);
		}

		tag = rlog->log_pos;
		struct fbr_log_line *log_line = (struct fbr_log_line*)(tag + 1);

		assert_dev(space > FBR_LOG_TYPE_SIZE);
		space -= FBR_LOG_TYPE_SIZE;

		va_list ap_copy;
		va_copy(ap_copy, ap);

		length = fbr_log_print_buf(log_line, space, type, rlog->request_id, fmt, ap_copy);
		fbr_logline_ok(log_line);

		va_end(ap_copy);

		if (log_line->truncated && retry) {
			space = 0;
			retry = 0;
			continue;
		}

		break;
	}

	*tag = fbr_log_tag_gen(0, FBR_LOG_TAG_LOGLINE, type, length);

	rlog->lines++;
	rlog->log_pos += FBR_TYPE_LENGTH(length) + 1;
	assert(rlog->log_pos <= rlog->log_end);

	if (rlog->log->always_flush) {
		fbr_rlog_flush(rlog);
	}
}

void __fbr_attr_printf(2)
fbr_rlog(enum fbr_log_type type, const char *fmt, ...)
{
	assert(type);
	assert(fmt && *fmt);

	if (fbr_log_type_masked(type)) {
		return;
	}

	va_list ap;
	va_start(ap, fmt);

	struct fbr_request *request = fbr_request_get();
	if (request) {
		fbr_request_ok(request);
		fbr_rlog_ok(request->rlog);

		_rlog_log(request->rlog, type, fmt, ap);
	} else {
		struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
		fbr_log_ok(fuse_ctx->log);

		fbr_log_vprint(fuse_ctx->log, type, FBR_REQID_CORE, fmt, ap);
	}

	va_end(ap);
}

void __fbr_attr_printf(3)
fbr_rdlog(struct fbr_rlog *rlog, enum fbr_log_type type, const char *fmt, ...)
{
	fbr_rlog_ok(rlog);
	fbr_log_ok(rlog->log);
	assert(type);
	assert(fmt && *fmt);

	if (fbr_log_type_masked(type)) {
		return;
	}

	va_list ap;
	va_start(ap, fmt);

	_rlog_log(rlog, type, fmt, ap);

	va_end(ap);
}

void
fbr_rlog_free(struct fbr_rlog **rlog_p)
{
	assert(rlog_p);

	struct fbr_rlog *rlog = *rlog_p;
	fbr_rlog_ok(rlog);
	*rlog_p = NULL;

	fbr_rlog_flush(rlog);

	fbr_ZERO(rlog);
}
