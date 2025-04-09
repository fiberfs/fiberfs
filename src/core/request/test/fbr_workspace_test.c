/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "core/request/fbr_workspace.h"

#include "test/fbr_test.h"
#include "fbr_test_request_cmds.h"

void
fbr_cmd_workspace_test_asserts(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("FBR_WORKSPACE_MIN_SIZE=%d", FBR_WORKSPACE_MIN_SIZE);
	fbr_test_logs("PATH_MAX=%d", PATH_MAX);
	fbr_test_logs("FBR_WORKSPACE_OVERFLOW_MAX=%d", FBR_WORKSPACE_OVERFLOW_MAX);
	fbr_test_logs("fbr_workspace_size()=%zu", fbr_workspace_size());
	fbr_test_logs("sizeof(struct fbr_workspace)=%zu", sizeof(struct fbr_workspace));

	fbr_ASSERT(PATH_MAX <= FBR_WORKSPACE_MIN_SIZE, "PATH_MAX > FBR_WORKSPACE_MIN_SIZE");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "workspace_test_asserts done");
}

void
fbr_cmd_workspace_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	char buffer1[1024 * 16];
	struct fbr_workspace *ws1 = fbr_workspace_init(buffer1, sizeof(buffer1));
	size_t buf1_len = 11;
	char *buf1 = fbr_workspace_alloc(ws1, buf1_len);
	snprintf(buf1, 11, "1234567890");
	assert(!strcmp(buf1, "1234567890"));
	size_t buf2_len = 1024 * 10;
	void *buf2 = fbr_workspace_alloc(ws1, buf2_len);
	memset(buf2, 0, buf2_len);
	void *buf3 = fbr_workspace_rbuffer(ws1);
	assert(ws1->reserved);
	assert_zero(ws1->reserved_ptr);
	(void)buf3;
	size_t buf3_len = fbr_workspace_rlen(ws1);
	assert(buf3_len == sizeof(buffer1) - sizeof(*ws1) - buf1_len - buf2_len);
	buf3_len -= 1024;
	fbr_workspace_ralloc(ws1, buf3_len);
	void *buf4 = fbr_workspace_rbuffer(ws1);
	assert(ws1->reserved);
	assert(ws1->reserved_ptr);
	(void)buf4;
	size_t buf4_len = fbr_workspace_rlen(ws1);
	assert(buf4_len == FBR_WORKSPACE_MIN_SIZE);
	assert(ws1->overflow_len == buf4_len);
	fbr_workspace_ralloc(ws1, buf4_len - 1024);
	void *buf5 = fbr_workspace_alloc(ws1, 1000);
	assert_zero(ws1->reserved);
	assert_zero(ws1->reserved_ptr);
	(void)buf5;
	void *buf6 = fbr_workspace_rbuffer(ws1);
	assert(ws1->reserved);
	assert(ws1->reserved_ptr);
	(void)buf6;
	size_t buf6_len = fbr_workspace_rlen(ws1);
	assert(buf6_len == FBR_WORKSPACE_MIN_SIZE);
	assert(ws1->overflow_len == buf4_len + buf6_len);
	fbr_workspace_ralloc(ws1, buf6_len);
	size_t buf7_len = 250;
	void *buf7 = fbr_workspace_alloc(ws1, buf7_len);
	memset(buf7, 1, buf7_len);
	fbr_workspace_debug(ws1, &fbr_test_logs);
	assert(ws1->free == 24);
	assert(ws1->overflow_len == buf4_len + buf6_len + buf7_len);
	fbr_workspace_free(ws1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "workspace_test done");
}
