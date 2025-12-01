/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 *
 */

#include <time.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "utils/fbr_chash.h"

size_t
fbr_cstore_s3_hash_none(void *priv, void *hash, size_t hash_len)
{
	assert_zero(priv);
	assert(hash);
	assert(hash_len >= FBR_HEX_LEN(FBR_SHA256_DIGEST_SIZE));

	size_t ret = fbr_strcpy(hash, hash_len,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

	return ret;
}

void
fbr_cstore_s3_sign(struct fbr_cstore *cstore, struct chttp_context *http, time_t sign_time,
    fbr_cstore_s3_hash_f hash_cb, void *hash_priv)
{
	fbr_cstore_ok(cstore);
	assert(cstore->s3.backend);
	chttp_context_ok(http);

	// TODO what if the url is on the next dpage?
	struct chttp_dpage *dpage = http->dpage;
	chttp_dpage_ok(dpage);
	size_t method_len = 0;
	size_t url_len = 0;
	for (size_t i = 0; i < dpage->length; i++) {
		char c = dpage->data[i];
		assert(c >= ' ' && c <= '~');
		if (c == ' ') {
			if (!method_len) {
				assert(i);
				method_len = i;
			} else {
				assert(i > method_len);
				url_len = i - method_len - 1;
				break;
			}
		}
	}
	assert(method_len);
	assert(url_len);
	const char *method = (char*)dpage->data;
	const char *url = (char*)dpage->data + method_len + 1;

	if (!sign_time) {
		sign_time = (time_t)fbr_get_time();
	}
	struct tm tm_sign;
	gmtime_r(&sign_time, &tm_sign);
	char amz_timestamp[32];
	size_t amz_timestamp_len = strftime(amz_timestamp, sizeof(amz_timestamp),
		"%Y%m%dT%H%M%SZ", &tm_sign);
	assert(amz_timestamp_len);
	char amz_date[32];
	size_t amz_date_len = strftime(amz_date, sizeof(amz_date), "%Y%m%d", &tm_sign);
	assert(amz_date_len);

	char amz_content[FBR_HEX_LEN(FBR_SHA256_DIGEST_SIZE)];
	size_t amz_content_len = 0;
	if (hash_cb && !cstore->skip_content_hash) {
		amz_content_len = hash_cb(hash_priv, amz_content, sizeof(amz_content));
	}
	if (!amz_content_len) {
		amz_content_len = fbr_strbcpy(amz_content, "UNSIGNED-PAYLOAD");
	}

	// Canonical Request
	struct fbr_sha256_ctx crequest;
	fbr_sha256_init(&crequest, 0);
	fbr_sha256_update(&crequest, method, method_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, url, url_len);
	fbr_sha256_update(&crequest, "\n\n", 2);
	fbr_sha256_update(&crequest, "host:", 5);
	fbr_sha256_update(&crequest, cstore->s3.backend->host, cstore->s3.backend->host_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, "x-amz-content-sha256:", 21);
	fbr_sha256_update(&crequest, amz_content, amz_content_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, "x-amz-date:", 11);
	fbr_sha256_update(&crequest, amz_timestamp, amz_timestamp_len);
	fbr_sha256_update(&crequest, "\n\nhost;x-amz-content-sha256;x-amz-date\n", 39);
	fbr_sha256_update(&crequest, amz_content, amz_content_len);

	uint8_t crequest_hash[FBR_SHA256_DIGEST_SIZE];
	char crequest_hex[FBR_HEX_LEN(sizeof(crequest_hash))];
	fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
	fbr_bin2hex(crequest_hash, sizeof(crequest_hash), crequest_hex, sizeof(crequest_hex));

	// Scope and signing string
	char amz_scope[128];
	fbr_bprintf(amz_scope, "%s/%s/s3/aws4_request", amz_date, cstore->s3.region);
	char amz_signing[256];
	size_t amz_signing_len = fbr_bprintf(amz_signing, "AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amz_timestamp, amz_scope, crequest_hex);
	assert_dev(amz_signing_len);

	// Signing keys and signature
	char key[128];
	size_t key_len = fbr_bprintf(key, "AWS4%s", cstore->s3.secret_key);
	assert_dev(key_len);
	uint8_t key_hashA[FBR_SHA256_DIGEST_SIZE];
	uint8_t key_hashB[FBR_SHA256_DIGEST_SIZE];

	struct fbr_sha256_ctx hmac;
	fbr_hmac_sha256_init(&hmac, key, key_len, 0);
	fbr_sha256_update(&hmac, amz_date, amz_date_len);
	fbr_hmac_sha256_final(&hmac, key, key_len, key_hashA, sizeof(key_hashA));

	explicit_bzero(key, sizeof(key));

	fbr_hmac_sha256_init(&hmac, key_hashA, sizeof(key_hashA), 0);
	fbr_sha256_update(&hmac, cstore->s3.region, cstore->s3.region_len);
	fbr_hmac_sha256_final(&hmac, key_hashA, sizeof(key_hashA), key_hashB, sizeof(key_hashB));

	fbr_hmac_sha256_init(&hmac, key_hashB, sizeof(key_hashB), 0);
	fbr_sha256_update(&hmac, "s3", 2);
	fbr_hmac_sha256_final(&hmac, key_hashB, sizeof(key_hashB), key_hashA, sizeof(key_hashA));

	fbr_hmac_sha256_init(&hmac, key_hashA, sizeof(key_hashA), 0);
	fbr_sha256_update(&hmac, "aws4_request", 12);
	fbr_hmac_sha256_final(&hmac, key_hashA, sizeof(key_hashA), key_hashB, sizeof(key_hashB));

	fbr_hmac_sha256_init(&hmac, key_hashB, sizeof(key_hashB), 0);
	fbr_sha256_update(&hmac, amz_signing, amz_signing_len);
	fbr_hmac_sha256_final(&hmac, key_hashB, sizeof(key_hashB), key_hashA, sizeof(key_hashA));

	char signature[FBR_HEX_LEN(sizeof(key_hashA))];
	fbr_bin2hex(key_hashA, sizeof(key_hashA), signature, sizeof(signature));

	// Authorization
	char amz_auth[512];
	fbr_bprintf(amz_auth,
		"AWS4-HMAC-SHA256 Credential=%s/%s, "
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
		"Signature=%s",
			cstore->s3.access_key, amz_scope, signature);

	chttp_header_add(http, "x-amz-date", amz_timestamp);
	chttp_header_add(http, "x-amz-content-sha256", amz_content);
	chttp_header_add(http, "Authorization", amz_auth);

	return;
}

int
fbr_cstore_s3_validate(struct fbr_cstore *cstore, struct chttp_context *http)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);

	fbr_rlog(FBR_LOG_CS_S3, "Authorization passed");

	return 0;
}
