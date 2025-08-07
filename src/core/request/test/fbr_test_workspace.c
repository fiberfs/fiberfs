/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/request/fbr_workspace.h"

#include "test/fbr_test.h"

void
fbr_cmd_workspace_test_asserts(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("FBR_WORKSPACE_MIN_SIZE=%d", FBR_WORKSPACE_MIN_SIZE);
	fbr_test_logs("FBR_PATH_MAX=%d", FBR_PATH_MAX);
	fbr_test_logs("FBR_WORKSPACE_OVERFLOW_MAX=%d", FBR_WORKSPACE_OVERFLOW_MAX);
	fbr_test_logs("fbr_workspace_size()=%zu", fbr_workspace_size());
	fbr_test_logs("sizeof(struct fbr_workspace)=%zu", sizeof(struct fbr_workspace));

	fbr_ASSERT(FBR_PATH_MAX <= FBR_WORKSPACE_MIN_SIZE, "FBR_PATH_MAX > FBR_WORKSPACE_MIN_SIZE");

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "workspace_test_asserts done");
}

void
fbr_cmd_workspace_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("*** ws1");

	char buffer1[1024 * 16];
	struct fbr_workspace *ws1 = fbr_workspace_init(buffer1, sizeof(buffer1));
	assert(ws1->data);
	assert(ws1->size == sizeof(buffer1) - sizeof(*ws1));
	assert_zero(ws1->pos);
	assert(ws1->free == ws1->size);
	size_t buf11_len = 11;
	char *buf11 = fbr_workspace_alloc(ws1, buf11_len);
	assert(buf11);
	snprintf(buf11, 11, "1234567890");
	assert(!strcmp(buf11, "1234567890"));
	assert(ws1->pos);
	assert_zero(ws1->reserved);
	assert_zero(ws1->reserved_ptr);
	assert_zero(ws1->overflow_len);
	size_t buf12_len = 1024 * 10;
	void *buf12 = fbr_workspace_alloc(ws1, buf12_len);
	assert(buf12);
	memset(buf12, 0, buf12_len);
	void *buf13 = fbr_workspace_rbuffer(ws1);
	assert(buf13);
	assert(ws1->reserved);
	assert_zero(ws1->reserved_ptr);
	size_t buf13_len = fbr_workspace_rlen(ws1);
	assert(buf13_len == sizeof(buffer1) - sizeof(*ws1) - buf11_len - buf12_len);
	buf13_len -= 1024;
	fbr_workspace_ralloc(ws1, buf13_len);
	void *buf14 = fbr_workspace_rbuffer(ws1);
	assert(buf14);
	assert(ws1->reserved);
	assert(ws1->reserved_ptr);
	size_t buf14_len = fbr_workspace_rlen(ws1);
	assert(buf14_len == FBR_WORKSPACE_MIN_SIZE);
	assert(ws1->overflow_len == buf14_len);
	fbr_workspace_ralloc(ws1, buf14_len - 1024);
	void *buf15 = fbr_workspace_alloc(ws1, 1000);
	assert(buf15);
	assert_zero(ws1->reserved);
	assert_zero(ws1->reserved_ptr);
	void *buf16 = fbr_workspace_rbuffer(ws1);
	assert(buf16);
	assert(ws1->reserved);
	assert(ws1->reserved_ptr);
	size_t buf16_len = fbr_workspace_rlen(ws1);
	assert(buf16_len == FBR_WORKSPACE_MIN_SIZE);
	assert(ws1->overflow_len == buf14_len + buf16_len);
	fbr_workspace_ralloc(ws1, buf16_len);
	size_t buf17_len = 250;
	void *buf17 = fbr_workspace_alloc(ws1, buf17_len);
	assert(buf17);
	memset(buf17, 1, buf17_len);
	fbr_workspace_debug(ws1, &fbr_test_logs_nl);
	assert(ws1->free == 24);
	assert(ws1->overflow_len == buf14_len + buf16_len + buf17_len);
	fbr_workspace_free(ws1);

	fbr_test_logs("*** ws2");

	char buffer2[sizeof(struct fbr_workspace) + FBR_WORKSPACE_MIN_SIZE];
	struct fbr_workspace *ws2 = fbr_workspace_init(buffer2, sizeof(buffer2));
	assert(ws2->size == FBR_WORKSPACE_MIN_SIZE);
	void *buf21 = fbr_workspace_rbuffer(ws2);
	assert(buf21);
	assert(fbr_workspace_rlen(ws2) >= FBR_WORKSPACE_MIN_SIZE);
	assert(ws2->reserved);
	assert_zero(ws2->reserved_ptr);
	fbr_workspace_ralloc(ws2, 0);
	assert(ws2->size == FBR_WORKSPACE_MIN_SIZE);
	assert_zero(ws2->pos);
	assert_zero(ws2->reserved);
	assert_zero(ws2->reserved_ptr);
	void *buf22 = fbr_workspace_rbuffer(ws2);
	assert(buf22);
	assert(fbr_workspace_rlen(ws2) >= FBR_WORKSPACE_MIN_SIZE);
	fbr_workspace_ralloc(ws2, 0);
	void *buf23 = fbr_workspace_rbuffer(ws2);
	assert(buf23);
	assert(fbr_workspace_rlen(ws2) >= FBR_WORKSPACE_MIN_SIZE);
	fbr_workspace_ralloc(ws2, 0);
	assert(ws2->size == FBR_WORKSPACE_MIN_SIZE);
	assert_zero(ws2->pos);
	assert(ws2->free == ws2->size);
	assert_zero(fbr_workspace_rlen(ws2));
	fbr_workspace_debug(ws2, &fbr_test_logs_nl);
	fbr_workspace_free(ws2);

	fbr_test_logs("*** ws3");

	struct fbr_workspace *ws3 = fbr_workspace_init(buffer2, sizeof(buffer2));
	assert(ws3->size == FBR_WORKSPACE_MIN_SIZE);
	size_t buf31_len = 33000;
	char *buf31 = fbr_workspace_alloc(ws3, buf31_len);
	assert(buf31);
	memset(buf31, 0, buf31_len);
	size_t buf32_len = 33000;
	char *buf32 = fbr_workspace_alloc(ws3, buf32_len);
	assert(buf32);
	memset(buf32, 0, buf32_len);
	size_t buf33_len = 33000;
	char *buf33 = fbr_workspace_alloc(ws3, buf33_len);
	assert_zero(buf33);
	size_t buf34_len = 3300;
	char *buf34 = fbr_workspace_alloc(ws3, buf34_len);
	assert(buf34);
	memset(buf34, 0, buf34_len);
	size_t buf35_len = 3300;
	char *buf35 = fbr_workspace_alloc(ws3, buf35_len);
	assert_zero(buf35);
	fbr_workspace_debug(ws3, &fbr_test_logs_nl);

	fbr_test_logs("*** ws3 (reset)");

	fbr_workspace_reset(ws3);
	assert_zero(ws3->pos);
	assert(ws3->size == FBR_WORKSPACE_MIN_SIZE);
	assert(ws3->free == ws3->size);
	assert_zero(ws3->overflow_len);
	buf33 = fbr_workspace_alloc(ws3, buf33_len);
	assert(buf33);
	memset(buf33, 0, buf33_len);
	buf35 = fbr_workspace_alloc(ws3, buf35_len);
	assert(buf35);
	memset(buf35, 0, buf35_len);
	void *buf36 = fbr_workspace_rbuffer(ws3);
	assert(buf36);
	size_t buf36_len = fbr_workspace_rlen(ws3);
	assert(buf36_len >= FBR_WORKSPACE_MIN_SIZE);
	fbr_workspace_ralloc(ws3, buf36_len);
	fbr_workspace_debug(ws3, &fbr_test_logs_nl);
	assert(ws3->pos == buf35_len);
	assert(ws3->overflow_len == buf33_len + buf36_len);
	fbr_workspace_free(ws3);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "workspace_test done");
}
