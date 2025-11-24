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
	char decode[FBR_PATH_MAX];

	char *input = "test.";
	size_t output_len = fbr_urlencode(input, 5, output, sizeof(output));
	fbr_urldecode(output, output_len, decode, sizeof(decode));
	fbr_test_logs("'%s' > '%s' > '%s'", input, output, decode);
	assert_zero(strcmp(output, "test."));
	assert_zero(strcmp(decode, input));

	input = "(test!)";
	output_len = fbr_urlencode(input, 8, output, sizeof(output));
	fbr_urldecode(output, output_len, decode, sizeof(decode));
	fbr_test_logs("'%s' > '%s' > '%s'", input, output, decode);
	assert_zero(strcmp(output, "%28test%21%29%00"));
	assert_zero(strcmp(decode, input));

	for (size_t i = 0; i < output_len; i++) {
		size_t decode_len = fbr_urldecode(output, output_len - i, decode, sizeof(decode));
		fbr_test_logs("'%.*s' > '%s':%zu", (int)(output_len - i), output, decode,
			decode_len);
		assert_zero(strncmp(decode, input, decode_len));
	}

	input = "안녕하세요";
	size_t input_len = strlen(input);
	assert(input_len == 15);
	output_len = fbr_urlencode(input, input_len, output, sizeof(output));
	size_t decode_len = fbr_urldecode(output, output_len, decode, sizeof(decode));
	fbr_test_logs("'%s':%zu > '%s'%zu > '%s'%zu", input, input_len, output, output_len,
		decode, decode_len);
	assert(output_len == 45);
	assert_zero(strcmp(output, "%EC%95%88%EB%85%95%ED%95%98%EC%84%B8%EC%9A%94"));
	assert(input_len == decode_len);
	assert_zero(strcmp(decode, input));

	input = "¥😊";
	input_len = strlen(input);
	assert(input_len == 6);
	output_len = fbr_urlencode(input, input_len, output, sizeof(output));
	decode_len = fbr_urldecode(output, output_len, decode, sizeof(decode));
	fbr_test_logs("'%s':%zu > '%s'%zu > '%s'%zu", input, input_len, output, output_len,
		decode, decode_len);
	assert(output_len == 18);
	assert_zero(strcmp(output, "%C2%A5%F0%9F%98%8A"));
	assert(input_len == decode_len);
	assert_zero(strcmp(decode, input));

	input = "€®";
	input_len = strlen(input);
	assert(input_len == 5);
	output_len = fbr_urlencode(input, input_len, output, sizeof(output));
	decode_len = fbr_urldecode(output, output_len, decode, sizeof(decode));
	fbr_test_logs("'%s':%zu > '%s'%zu > '%s'%zu", input, input_len, output, output_len,
		decode, decode_len);
	assert(output_len == 15);
	assert_zero(strcmp(output, "%E2%82%AC%C2%AE"));
	assert(input_len == decode_len);
	assert_zero(strcmp(decode, input));

	char path[PATH_MAX];
	memset(path, 0, sizeof(path));
	for (size_t i = 0; i + input_len < sizeof(path);) {
		memcpy(path + i, input, input_len);
		i += input_len;
	}
	size_t path_len = strlen(path);
	assert(path_len + 1 == sizeof(path));
	output_len = fbr_urlencode(path, path_len, output, sizeof(output));
	decode_len = fbr_urldecode(output, output_len, decode, sizeof(decode));
	fbr_test_logs("'...':%zu > '...':%zu > '...':%zu", path_len, output_len, decode_len);
	assert(output_len == path_len * 3);
	for (size_t i = 0; i < output_len;) {
		assert_zero(strncmp(output + i, "%E2%82%AC%C2%AE", 15));
		i += 15;
	}
	assert(path_len == decode_len);
	assert_zero(strcmp(decode, path));

	char buffer[50];
	fbr_strbcpy(buffer, "%54%45%53%54%74%65%73%74");
	size_t buffer_len = strlen(buffer);
	fbr_test_logs("BEFORE '%s':%zu", buffer, buffer_len);
	buffer_len = fbr_urldecode(buffer, buffer_len, buffer, sizeof(buffer));
	fbr_test_logs("AFTER  '%s':%zu", buffer, buffer_len);
	assert_zero(strcmp(buffer, "TESTtest"));

	fbr_strbcpy(buffer, "t%54e%45s%53t%54T%74E%65S%73T%74!");
	buffer_len = strlen(buffer);
	fbr_test_logs("BEFORE '%s':%zu", buffer, buffer_len);
	buffer_len = fbr_urldecode(buffer, buffer_len, buffer, sizeof(buffer));
	fbr_test_logs("AFTER  '%s':%zu", buffer, buffer_len);
	assert_zero(strcmp(buffer, "tTeEsStTTtEeSsTt!"));

	fbr_test_logs("test_urlencode passed");
}
