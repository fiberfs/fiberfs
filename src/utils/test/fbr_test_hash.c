/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "test/fbr_test.h"

static void
_test_hex(const void *buffer, size_t buffer_len)
{
	char hex_buf[1024 * 2 + 1];
	size_t hex_len = fbr_bin2hex(buffer, buffer_len, hex_buf, sizeof(hex_buf));
	fbr_test_logs("hex: '%s':%zu", hex_buf, hex_len);

	char bin_buf[1024];
	size_t bin_len = fbr_hex2bin(hex_buf, hex_len, bin_buf, sizeof(bin_buf));
	assert(bin_len == buffer_len);
	assert_zero(memcmp(buffer, bin_buf, bin_len));
}

static void
_test_hash(const void *buffer, size_t buffer_len)
{
	fbr_hash_t h1 = fbr_hash(buffer, buffer_len);
	fbr_test_logs("hash(%zu)=%lu", buffer_len, h1);

	_test_hex(&h1, sizeof(h1));
}

void
fbr_cmd_test_hash(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_hash("test", 4);
	_test_hash("test", 5);
	_test_hash("", 0);

	uint8_t buffer[1024];
	fbr_test_fill_random(buffer, sizeof(buffer));
	_test_hash(buffer, sizeof(buffer));
	fbr_test_fill_random(buffer, sizeof(buffer));
	_test_hash(buffer, sizeof(buffer));
	fbr_test_fill_random(buffer, sizeof(buffer));
	_test_hash(buffer, sizeof(buffer) - 250);

	fbr_zero(buffer);
	_test_hex(buffer, sizeof(buffer));

	fbr_test_logs("test_hash passed");
}
