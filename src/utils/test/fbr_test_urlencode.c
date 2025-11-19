/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>

#include "fiberfs.h"
#include "test/fbr_test.h"

void
fbr_cmd_test_urlencode(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	char output[FBR_URL_MAX];

	char *input = "test.";
	fbr_urlencode(input, 5, output, sizeof(output));
	fbr_test_logs("'%s' > '%s'", input, output);
	assert_zero(strcmp(output, "test."));

	input = "(test!)";
	fbr_urlencode(input, 8, output, sizeof(output));
	fbr_test_logs("'%s' > '%s'", input, output);
	assert_zero(strcmp(output, "%28test%21%29%00"));

	input = "안녕하세요";
	size_t input_len = strlen(input);
	assert(input_len == 15);
	size_t output_len = fbr_urlencode(input, input_len, output, sizeof(output));
	fbr_test_logs("'%s':%zu > '%s'%zu", input, input_len, output, output_len);
	assert(output_len == 45);
	assert_zero(strcmp(output, "%EC%95%88%EB%85%95%ED%95%98%EC%84%B8%EC%9A%94"));

	input = "¥😊";
	input_len = strlen(input);
	assert(input_len == 6);
	output_len = fbr_urlencode(input, input_len, output, sizeof(output));
	fbr_test_logs("'%s':%zu > '%s'%zu", input, input_len, output, output_len);
	assert(output_len == 18);
	assert_zero(strcmp(output, "%C2%A5%F0%9F%98%8A"));

	input = "€®";
	input_len = strlen(input);
	assert(input_len == 5);
	output_len = fbr_urlencode(input, input_len, output, sizeof(output));
	fbr_test_logs("'%s':%zu > '%s'%zu", input, input_len, output, output_len);
	assert(output_len == 15);
	assert_zero(strcmp(output, "%E2%82%AC%C2%AE"));

	char path[PATH_MAX];
	memset(path, 0, sizeof(path));
	for (size_t i = 0; i + input_len < sizeof(path);) {
		memcpy(path + i, input, input_len);
		i += input_len;
	}
	size_t path_len = strlen(path);
	assert(path_len + 1 == sizeof(path));
	output_len = fbr_urlencode(path, path_len, output, sizeof(output));
	fbr_test_logs("'...':%zu > '...'%zu", path_len, output_len);
	assert(output_len == path_len * 3);
	for (size_t i = 0; i < output_len;) {
		assert_zero(strncmp(output + i, "%E2%82%AC%C2%AE", 15));
		i += 15;
	}

	fbr_test_logs("test_urlencode passed");
}
