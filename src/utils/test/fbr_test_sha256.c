/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "utils/fbr_sha256.h"

#include "test/fbr_test.h"

void
fbr_cmd_test_sha256(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_sha256_ctx sha;
	unsigned char digest[FBR_SHA256_DIGEST_SIZE];
	char hex[(sizeof(digest) * 2) + 1];

	fbr_sha256("", 0, digest);
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256()=%s", hex);
	assert(!strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

	fbr_sha256_init(&sha);
	fbr_sha256_update(&sha, "fiber", 5);
	fbr_sha256_update(&sha, "fs", 2);
	fbr_sha256_final(&sha, digest);
	size_t hex_len = fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(fiberfs)=%s", hex);
	assert(!strcmp(hex, "45704c9bb9402367abea4241a23c777c3a625ed50fb38ad0a25f4c668403062b"));

	fbr_sha256_init(&sha);
	for (size_t i = 0; i < hex_len; i++) {
		fbr_sha256_update(&sha, &hex[i], 1);
	}
	fbr_sha256_final(&sha, digest);
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(fiberfs^2)=%s", hex);

	fbr_test_random_seed();

	size_t size = 1000000;
	char buffer[23196];
	memset(buffer, 'a', sizeof(buffer));
	fbr_sha256_init(&sha);
	while (size) {
		size_t hash_len = size % random();
		if (hash_len > sizeof(buffer)) {
			hash_len = sizeof(buffer);
		}
		assert(hash_len <= size);
		fbr_sha256_update(&sha, buffer, hash_len);
		size -= hash_len;
	}
	fbr_sha256_final(&sha, digest);
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(a x 1000000)=%s", hex);
	assert(!strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

	fbr_test_logs("test_sha256 passed");
}
