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
#include "log/fbr_log.h"

#include "test/fbr_test.h"

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

	_rlog_init(request->rlog, rlog_size, request->id);
}

static struct fbr_log *
_rlog_get_log(void)
{
	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	fbr_log_ok(fuse_ctx->log);
	return fuse_ctx->log;
}

void
fbr_rlog_flush(struct fbr_rlog *rlog)
{
	fbr_rlog_ok(rlog);

	if (!rlog->lines) {
		assert_dev(rlog->log_pos == rlog->data);
		return;
	}

	assert(rlog->log_pos > rlog->data);
	size_t length = (rlog->log_pos - rlog->data) * FBR_LOG_TYPE_SIZE;

	struct fbr_log *log = _rlog_get_log();
	fbr_log_batch(log, rlog->data, length, rlog->lines);

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
}

static void
_rlog_test_log(enum fbr_log_type type, unsigned long request_id, const char *fmt, va_list ap)
{
	assert(fbr_is_test());

	if (!fbr_test_can_log(NULL, FBR_LOG_VERBOSE)) {
		return;
	}

	double time = fbr_log_test_time();

	char vbuf[FBR_LOGLINE_MAX_LENGTH];
	(void)vsnprintf(vbuf, sizeof(vbuf), fmt, ap);

	const char *type_str = fbr_log_type_str(type);

	char reqid_str[32];
	fbr_log_reqid_str(request_id, reqid_str, sizeof(reqid_str));

	printf("##%.3f %s:%s %s\n", time, type_str, reqid_str, vbuf);
}

static void
_flog(enum fbr_log_type type, unsigned long request_id, const char *fmt, va_list ap)
{
	assert_dev(type);
	assert_dev(request_id);
	assert_dev(fmt && *fmt);

	if (!fbr_fuse_has_context()) {
		_rlog_test_log(type, request_id, fmt, ap);
		return;
	}

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	fbr_log_ok(fuse_ctx->log);

	fbr_log_vprint(fuse_ctx->log, type, request_id, fmt, ap);
}

static void
_rlog(enum fbr_log_type type, const char *fmt, va_list ap)
{
	assert_dev(type);
	assert_dev(fmt && *fmt);

	struct fbr_request *request = fbr_request_get();
	if (!request) {
		_flog(type, FBR_REQID_CORE, fmt, ap);
		return;
	}

	fbr_request_ok(request);
	fbr_rlog_ok(request->rlog);

	_rlog_log(request->rlog, type, fmt, ap);
}

void __fbr_attr_printf(2)
fbr_rlog(enum fbr_log_type type, const char *fmt, ...)
{
	assert(type);
	assert(fmt && *fmt);

	va_list ap;
	va_start(ap, fmt);

	_rlog(type, fmt, ap);

	va_end(ap);
}

void __fbr_attr_printf(3)
fbr_flog(enum fbr_log_type type, unsigned long request_id, const char *fmt, ...)
{
	assert(type);
	assert(request_id);
	assert(fmt && *fmt);

	va_list ap;
	va_start(ap, fmt);

	_flog(type, request_id, fmt, ap);

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
