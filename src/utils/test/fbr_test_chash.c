/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#ifdef CHTTP_OPENSSL
#include "openssl/sha.h"
#endif

#include "fiberfs.h"
#include "tls/chttp_tls.h"
#include "utils/fbr_chash.h"

#include "test/fbr_test.h"

void
fbr_cmd_test_sha256(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_sha256_ctx sha;
	uint8_t digest[FBR_SHA256_DIGEST_SIZE];
	char hex[(sizeof(digest) * 2) + 1];

	fbr_sha256("", 0, digest, sizeof(digest));
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256()=%s", hex);
	assert(!strcmp(hex, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

	fbr_sha256_init(&sha);
	fbr_sha256_update(&sha, "fiber", 5);
	fbr_sha256_update(&sha, "fs", 2);
	fbr_sha256_final(&sha, digest, sizeof(digest));
	size_t hex_len = fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(fiberfs)=%s", hex);
	assert(!strcmp(hex, "45704c9bb9402367abea4241a23c777c3a625ed50fb38ad0a25f4c668403062b"));

	fbr_sha256_init(&sha);
	for (size_t i = 0; i < hex_len; i++) {
		fbr_sha256_update(&sha, &hex[i], 1);
	}
	fbr_sha256_final(&sha, digest, sizeof(digest));
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
	fbr_sha256_final(&sha, digest, sizeof(digest));
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(a x 1000000)=%s", hex);
	assert(!strcmp(hex, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"));

	// 5GB openssl test
	/*
	char buf2[1024 * 1024];
	memset(buf2, 0, sizeof(buf2));
	size_t bytes = 0;
	double now = fbr_get_time();
	SHA256_CTX sha_openssl;
	uint8_t digest_openssl[FBR_SHA256_DIGEST_SIZE];
	fbr_sha256_init(&sha);
	SHA256_Init(&sha_openssl);
	for (size_t i = 0; i < 5120; i++) {
		fbr_sha256_update(&sha, buf2, sizeof(buf2));
		SHA256_Update(&sha_openssl, buf2, sizeof(buf2));
		bytes += sizeof(buf2);
	}
	fbr_sha256_update(&sha, buf2, 20);
	SHA256_Update(&sha_openssl, buf2, 20);
	fbr_sha256_final(&sha, digest, sizeof(digest));
	SHA256_Final(digest_openssl, &sha_openssl);
	double diff = fbr_get_time() - now;
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(###BIGBIGBIG)=%s", hex);
	fbr_bin2hex(digest_openssl, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("sha256(###__openssl)=%s", hex);
	fbr_test_logs("bytes=%zu MB", bytes / 1024 / 1024);
	fbr_test_logs("time=%lf", diff);
	assert_zero(memcmp(digest, digest_openssl, sizeof(digest)));
	*/

	fbr_test_logs("test_sha256 passed");
}

void
fbr_cmd_test_hmac_sha256(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_sha256_ctx hmac;
	uint8_t digest[FBR_SHA256_DIGEST_SIZE];
	char hex[(sizeof(digest) * 2) + 1];

	const char *key1 = "secret_key";
	size_t key1_len = strlen(key1);
	fbr_hmac_sha256_init(&hmac, key1, key1_len);
	fbr_sha256_update(&hmac, "Hello", 5);
	fbr_hmac_sha256_final(&hmac, key1, key1_len, digest, sizeof(digest));
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("hmac(%s, Hello)=%s", key1, hex);
	assert(!strcmp(hex, "0f0d2e10ec2bdf21bbdf490fd103820089879277261e9aa53ce3f8ecfd46b687"));

	const char *key2 = "key";
	size_t key2_len = strlen(key2);
	const char *msg2 = "The quick brown fox jumps over the lazy dog";
	fbr_hmac_sha256_init(&hmac, key2, key2_len);
	for (size_t i = 0; i < strlen(msg2); i++) {
		fbr_sha256_update(&hmac, &msg2[i], 1);
	}
	fbr_hmac_sha256_final(&hmac, key2, key2_len, digest, sizeof(digest));
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("hmac(%s, %s)=%s", key2, msg2, hex);
	assert(!strcmp(hex, "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"));

	const char *key3 =
		"12345678901234567890123456789012345678901234567890"
		"12345678901234567890123456789012345678901234567890";
	size_t key3_len = strlen(key3);
	const char *msg3 = "key is 100 bytes";
	fbr_hmac_sha256_init(&hmac, key3, key3_len);
	fbr_sha256_update(&hmac, msg3, strlen(msg3));
	fbr_hmac_sha256_final(&hmac, key3, key3_len, digest, sizeof(digest));
	fbr_bin2hex(digest, sizeof(digest), hex, sizeof(hex));
	fbr_test_logs("hmac(100, %s)=%s", msg3, hex);
	assert(!strcmp(hex, "706b60111b13db5a2c73fc77eb801f987d7d2c75ec214a7ce0c981df1b098b2d"));

	fbr_test_logs("test_hmac_sha256 passed");
}

void
fbr_cmd_test_md5(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_md5_ctx md5;
	char hex[(FBR_MD5_DIGEST_SIZE * 2) + 1];

	fbr_md5_init(&md5);
	fbr_md5_update(&md5, NULL, 0);
	fbr_md5_final(&md5);
	fbr_bin2hex(md5.digest, sizeof(md5.digest), hex, sizeof(hex));
	fbr_test_logs("md5()=%s", hex);
	assert(!strcmp(hex, "d41d8cd98f00b204e9800998ecf8427e"));

	fbr_md5_init(&md5);
	fbr_md5_update(&md5, "abc", 3);
	fbr_md5_final(&md5);
	fbr_bin2hex(md5.digest, sizeof(md5.digest), hex, sizeof(hex));
	fbr_test_logs("md5(abc)=%s", hex);
	assert(!strcmp(hex, "900150983cd24fb0d6963f7d28e17f72"));

	const char *s = "The quick brown fox jumps over the lazy dog.";
	fbr_md5_init(&md5);
	for (size_t i = 0; i < strlen(s); i++) {
		fbr_md5_update(&md5, &s[i], 1);
	}
	fbr_md5_final(&md5);
	fbr_bin2hex(md5.digest, sizeof(md5.digest), hex, sizeof(hex));
	fbr_test_logs("md5(%s)=%s", s, hex);
	assert(!strcmp(hex, "e4d909c290d0fb1ca068ffaddf22cbd0"));

	fbr_test_logs("test_md5 passed");
}

void
fbr_cmd_test_sha256_openssl(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	if (!chttp_tls_enabled()) {
		fbr_test_logs("test_sha256_open skipped");
		return;
	}

#ifdef CHTTP_OPENSSL
	fbr_test_random_seed();

	char all_a[5000];
	memset(all_a, 'a', sizeof(all_a));

	struct fbr_sha256_ctx sha;
	SHA256_CTX sha_openssl;
	uint8_t digest[FBR_SHA256_DIGEST_SIZE];
	uint8_t digest_open[SHA256_DIGEST_LENGTH];
	static_ASSERT(FBR_SHA256_DIGEST_SIZE == SHA256_DIGEST_LENGTH);
	size_t i;

	for (i = 0; i <= sizeof(all_a); i++) {
		fbr_sha256_init(&sha);
		if (i <= 512) {
			fbr_sha256_update(&sha, all_a, i);
		} else {
			size_t j = 0;
			while (j < i) {
				size_t remain = i - j;
				size_t bytes = (random() % remain) + (random() % 2);
				assert(bytes <= remain);

				fbr_sha256_update(&sha, all_a, bytes);

				j += bytes;
			}
			assert(j == i);
		}
		fbr_sha256_final(&sha, digest, sizeof(digest));

		SHA256_Init(&sha_openssl);
		SHA256_Update(&sha_openssl, all_a, i);
		SHA256_Final(digest_open, &sha_openssl);

		fbr_ASSERT(!memcmp(digest, digest_open, sizeof(digest)), "sha256 failed: %zu", i);
	}

	fbr_test_logs("openssl sha256 checksums passed: %zu", i);
	assert(i == sizeof(all_a) + 1);

	fbr_test_logs("test_sha256_open passed");
#else
	fbr_ABORT("TLS not configured");
#endif
}
