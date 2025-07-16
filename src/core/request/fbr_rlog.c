/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "log/fbr_log.h"

static void
_rlog_init(struct fbr_rlog *rlog, size_t rlog_size)
{
	assert_dev(rlog);
	assert(rlog_size > sizeof(*rlog));
	assert(rlog_size < FBR_LOG_SEGMENT_MIN_SIZE); // TODO

	fbr_ZERO(rlog);

	rlog->magic = FBR_RLOG_MAGIC;
	rlog->log_end = rlog->data + ((rlog_size - sizeof(*rlog)) / FBR_LOG_TYPE_SIZE);
	rlog->log_pos = rlog->data;
	assert(rlog->log_pos < rlog->log_end);

	fbr_rlog_ok(rlog);
}

void
fbr_rlog_workspace_alloc(struct fbr_request *request)
{
	fbr_request_ok(request);
	assert_zero(request->rlog);

	// TODO pull this from fs->config
	size_t rlog_size = FBR_RLOG_MIN_SIZE;

	request->rlog = fbr_workspace_alloc(request->workspace, rlog_size);
	assert(request->rlog);

	_rlog_init(request->rlog, rlog_size);
}

void __fbr_attr_printf(2)
fbr_rlog(enum fbr_log_type type, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	struct fbr_request *request = fbr_request_get();

	if (!request) {
		fbr_ASSERT(fbr_is_test(), "request context missing");

		vprintf(fmt, ap);
		va_end(ap);

		return;
	}
	fbr_request_ok(request);

	struct fbr_rlog *rlog = request->rlog;
	fbr_rlog_ok(rlog);
	assert_dev(rlog->log_pos <= rlog->log_end);

	size_t space = (rlog->log_end - rlog->log_pos) * FBR_LOG_TYPE_SIZE;

	if (space < 128) {
		fbr_ABORT("TODO");
	}

	fbr_log_data_t *tag = rlog->log_pos;
	struct fbr_log_line *log_line = (struct fbr_log_line*)(tag + 1);

	assert_dev(space > FBR_LOG_TYPE_SIZE);
	space -= FBR_LOG_TYPE_SIZE;

	size_t length = fbr_log_print_buf(log_line, space, type, request->id, fmt, ap);
	fbr_logline_ok(log_line);

	if (log_line->truncated) {
		fbr_ABORT("TODO")
	}

	*tag = fbr_log_tag_gen(0, FBR_LOG_TAG_LOGLINE, type, length);

	// TODO we need to sequence when appending the batch

	va_end(ap);
}

void
fbr_rlog_free(struct fbr_rlog **rlog_p)
{
	assert(rlog_p);

	struct fbr_rlog *rlog = *rlog_p;
	fbr_rlog_ok(rlog);
	*rlog_p = NULL;

	// TODO flush the log

	fbr_ZERO(rlog);
}
