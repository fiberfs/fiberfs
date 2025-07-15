/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_request.h"
#include "log/fbr_log.h"

void
fbr_rlog_alloc(struct fbr_request *request)
{
	fbr_request_ok(request);
	assert_zero(request->rlog);

	// TODO pull this from fs->config
	size_t rlog_size = FBR_RLOG_MIN_SIZE;
	assert(rlog_size > sizeof(*request->rlog));
	// TODO sort out these limits
	assert(rlog_size < FBR_LOG_SEGMENT_MIN_SIZE);

	struct fbr_rlog *rlog = fbr_workspace_alloc(request->workspace, rlog_size);
	assert(rlog);

	fbr_ZERO(rlog);

	rlog->magic = FBR_RLOG_MAGIC;
	rlog->capacity = rlog_size - sizeof(*rlog);

	request->rlog = rlog;
	fbr_rlog_ok(request->rlog);
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

	//fbr_log_vprint(log, type, request_id, fmt, ap);
	(void)type;

	va_end(ap);
}

void
fbr_rlog_free(struct fbr_request *request)
{
	fbr_request_ok(request);
	fbr_rlog_ok(request->rlog);

	// TODO flush the log

	fbr_ZERO(request->rlog);
	request->rlog = NULL;
}
