/*
 * Copyright (c) 2024-2026 FiberFS LLC
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

static void
_s3_signature(const char *secret_key, const char *date, size_t date_len,
    const char *timestamp, const char *canonical_hex, const char *region, size_t region_len,
    const char *scope, size_t scope_len, char *signature_buffer, size_t buffer_len)
{
	assert_dev(secret_key);
	assert_dev(date && date_len);
	assert_dev(timestamp);
	assert_dev(canonical_hex);
	assert_dev(region && region_len);
	assert_dev(scope && scope_len);
	assert_dev(signature_buffer && buffer_len);

	// Signing string
	char signing[256];
	size_t signing_len = fbr_bprintf(signing, "AWS4-HMAC-SHA256\n%s\n%.*s\n%s",
		timestamp, (int)scope_len, scope, canonical_hex);
	assert_dev(signing_len);

	// Signing keys and signature
	char key[128];
	size_t key_len = fbr_bprintf(key, "AWS4%s", secret_key);
	assert_dev(key_len);
	uint8_t key_hashA[FBR_SHA256_DIGEST_SIZE];
	uint8_t key_hashB[FBR_SHA256_DIGEST_SIZE];

	struct fbr_sha256_ctx hmac;
	fbr_hmac_sha256_init(&hmac, key, key_len, 0);
	fbr_sha256_update(&hmac, date, date_len);
	fbr_hmac_sha256_final(&hmac, key, key_len, key_hashA, sizeof(key_hashA));

	explicit_bzero(key, sizeof(key));

	fbr_hmac_sha256_init(&hmac, key_hashA, sizeof(key_hashA), 0);
	fbr_sha256_update(&hmac, region, region_len);
	fbr_hmac_sha256_final(&hmac, key_hashA, sizeof(key_hashA), key_hashB, sizeof(key_hashB));

	fbr_hmac_sha256_init(&hmac, key_hashB, sizeof(key_hashB), 0);
	fbr_sha256_update(&hmac, "s3", 2);
	fbr_hmac_sha256_final(&hmac, key_hashB, sizeof(key_hashB), key_hashA, sizeof(key_hashA));

	fbr_hmac_sha256_init(&hmac, key_hashA, sizeof(key_hashA), 0);
	fbr_sha256_update(&hmac, "aws4_request", 12);
	fbr_hmac_sha256_final(&hmac, key_hashA, sizeof(key_hashA), key_hashB, sizeof(key_hashB));

	fbr_hmac_sha256_init(&hmac, key_hashB, sizeof(key_hashB), 0);
	fbr_sha256_update(&hmac, signing, signing_len);
	fbr_hmac_sha256_final(&hmac, key_hashB, sizeof(key_hashB), key_hashA, sizeof(key_hashA));

	fbr_bin2hex(key_hashA, sizeof(key_hashA), signature_buffer, buffer_len);
}

void
fbr_cstore_s3_autosign(struct fbr_cstore *cstore, struct chttp_context *http,
    fbr_cstore_s3_hash_f hash_cb, void *hash_priv)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_backend_ok(cstore->s3.backend);

	fbr_cstore_s3_sign(http, 0, cstore->skip_content_hash, hash_cb, hash_priv,
		cstore->s3.backend->host, cstore->s3.backend->host_len, cstore->s3.region,
		cstore->s3.region_len, cstore->s3.access_key, cstore->s3.access_key_len,
		cstore->s3.secret_key);
}

void
fbr_cstore_s3_sign(struct chttp_context *http, time_t sign_time, int skip_content_hash,
    fbr_cstore_s3_hash_f hash_cb, void *hash_priv, const char *host, size_t host_len,
    const char *region, size_t region_len, const char *access_key, size_t access_key_len,
    const char *secret_key)
{
	chttp_context_ok(http);
	assert(host);
	assert(region && region_len);
	assert(access_key && access_key_len);
	assert(secret_key);

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
	char timestamp[32];
	size_t timestamp_len = strftime(timestamp, sizeof(timestamp),
		"%Y%m%dT%H%M%SZ", &tm_sign);
	assert(timestamp_len);
	char date[32];
	size_t date_len = strftime(date, sizeof(date), "%Y%m%d", &tm_sign);
	assert(date_len);

	char context_hex[FBR_HEX_LEN(FBR_SHA256_DIGEST_SIZE)];
	size_t content_hex_len = 0;
	if (hash_cb && !skip_content_hash) {
		content_hex_len = hash_cb(hash_priv, context_hex, sizeof(context_hex));
	}
	if (!content_hex_len) {
		content_hex_len = fbr_strbcpy(context_hex, "UNSIGNED-PAYLOAD");
	}

	// Canonical Request
	struct fbr_sha256_ctx crequest;
	fbr_sha256_init(&crequest, 0);
	fbr_sha256_update(&crequest, method, method_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, url, url_len);
	fbr_sha256_update(&crequest, "\n\n", 2);
	fbr_sha256_update(&crequest, "host:", 5);
	fbr_sha256_update(&crequest, host, host_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, "x-amz-content-sha256:", 21);
	fbr_sha256_update(&crequest, context_hex, content_hex_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, "x-amz-date:", 11);
	fbr_sha256_update(&crequest, timestamp, timestamp_len);
	fbr_sha256_update(&crequest, "\n\nhost;x-amz-content-sha256;x-amz-date\n", 39);
	fbr_sha256_update(&crequest, context_hex, content_hex_len);

	uint8_t crequest_hash[FBR_SHA256_DIGEST_SIZE];
	char crequest_hex[FBR_HEX_LEN(sizeof(crequest_hash))];
	fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
	fbr_bin2hex(crequest_hash, sizeof(crequest_hash), crequest_hex, sizeof(crequest_hex));

	// Scope
	char scope[128];
	size_t scope_len = fbr_bprintf(scope, "%s/%s/s3/aws4_request", date, region);

	// Signature
	char signature[FBR_HEX_LEN(FBR_SHA256_DIGEST_SIZE)];
	_s3_signature(secret_key, date, date_len, timestamp, crequest_hex,
		region, region_len, scope, scope_len, signature, sizeof(signature));

	// Authorization
	char authorization[512];
	fbr_bprintf(authorization,
		"AWS4-HMAC-SHA256 Credential=%s/%s, "
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date, "
		"Signature=%s",
			access_key, scope, signature);

	chttp_header_add(http, "x-amz-date", timestamp);
	chttp_header_add(http, "x-amz-content-sha256", context_hex);
	chttp_header_add(http, "Authorization", authorization);

	return;
}

static size_t
_s3_next_token(const char *string, const char **next, char seperator, char trim, char end)
{
	assert(next);

	if (!string) {
		*next = NULL;
		return 0;
	}

	char find[2];
	find[0] = seperator;
	find[1] = '\0';

	size_t len;
	*next = strstr(string, find);
	if (!*next) {
		if (end) {
			find[0] = end;
			char *endp = strstr(string, find);
			if (endp) {
				len = endp - string;
			} else {
				len = strlen(string);
			}
		} else {
			len = strlen(string);
		}
	} else  {
		len = *next - string;
		while (**next == seperator) {
			(*next)++;
		}
	}

	while (trim && len > 0 && string[len - 1] == trim) {
		len--;
	}

	return len;
}

int
fbr_cstore_s3_validate(struct fbr_cstore *cstore, struct chttp_context *http)
{
	fbr_cstore_ok(cstore);
	chttp_context_ok(http);

	const char *authorization = chttp_header_get(http, "Authorization");
	if (!authorization) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing Authorization missing");
		return 1;
	} else if (!cstore->s3.region_len || !cstore->s3.access_key_len ||
	    !cstore->s3.secret_key_len) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR cstore.s3 missing");
		return 1;
	}

	const char *next;
	const char *algorithm = authorization;
	size_t algorithm_len = _s3_next_token(algorithm, &next, ' ', ',', 0);

	const char *credential = next;
	size_t credential_len = _s3_next_token(credential, &next, ' ', ',', 0);

	const char *headers = next;
	size_t headers_len = _s3_next_token(headers, &next, ' ', ',', 0);

	const char *signature = next;
	size_t signature_len = _s3_next_token(signature, &next, ' ', ',', 0);

	if (strncmp(algorithm, "AWS4-HMAC-SHA256", algorithm_len)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad alg");
		return 1;
	} else if (!credential || credential_len <= 11 || strncmp(credential, "Credential=", 11)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad cred");
		return 1;
	} else if (!headers || headers_len <= 14 || strncmp(headers, "SignedHeaders=", 14)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad headers");
		return 1;
	} else if (!signature || signature_len <= 10 || strncmp(signature, "Signature=", 10)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad sig");
		return 1;
	} else if (next) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing next exists");
		return 1;
	}

	credential += 11;
	credential_len -= 11;
	headers += 14;
	headers_len -= 14;
	signature += 10;
	signature_len -= 10;

	(void)credential_len;

	const char *access_key = credential;
	size_t access_key_len = _s3_next_token(credential, &next, '/', 0, ',');

	const char *date = next;
	size_t date_len = _s3_next_token(date, &next, '/', 0, ',');

	const char *region = next;
	size_t region_len = _s3_next_token(region, &next, '/', 0, ',');

	const char *service = next;
	size_t service_len = _s3_next_token(service, &next, '/', 0, ',');

	const char *request = next;
	size_t request_len = _s3_next_token(request, &next, '/', 0, ',');

	if (!access_key || !access_key_len || !date || !date_len || !region || !region_len ||
	    !service || !service_len || !request || !request_len || next) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad cred content");
		return 1;
	} else if (service_len != 2 || strncmp(service, "s3", service_len)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad cred service");
		return 1;
	} else if (request_len != 12 || strncmp(request, "aws4_request", request_len)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad cred request");
		return 1;
	} else if (region_len != cstore->s3.region_len ||
	    strncmp(region, cstore->s3.region, region_len)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad cred region");
		return 1;
	} else if (access_key_len != cstore->s3.access_key_len ||
	    strncmp(access_key, cstore->s3.access_key, access_key_len)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR signing bad cred access key");
		return 1;
	}

	const char *scope = date;
	size_t scope_len = date_len + 1 + region_len + 1 + service_len + 1 + request_len;

	const char *method = chttp_header_get_method(http);
	assert(method);
	const char *url = chttp_header_get_url(http);
	assert(url);

	char context_hex[FBR_HEX_LEN(FBR_SHA256_DIGEST_SIZE)];
	size_t content_hex_len = 0;
	char timestamp[32];
	size_t timestamp_len = 0;

	// Canonical Requests
	uint8_t crequest_hash[FBR_SHA256_DIGEST_SIZE];
	struct fbr_sha256_ctx crequest;
	fbr_sha256_init(&crequest, 0);
	fbr_sha256_update(&crequest, method, strlen(method));
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, url, strlen(url));
	fbr_sha256_update(&crequest, "\n\n", 2);

	const char *header = headers;
	size_t header_len;

	while ((header_len = _s3_next_token(header, &next, ';', 0, ','))) {
		if (header_len >= 256) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR signing big header");
			fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
			return 1;
		}

		fbr_sha256_update(&crequest, header, header_len);
		fbr_sha256_update(&crequest, ":", 1);

		char header_buf[256];
		memcpy(header_buf, header, header_len);
		header_buf[header_len] = '\0';

		const char *header_value = chttp_header_get(http, header_buf);
		if (!header_value) {
			fbr_rlog(FBR_LOG_CS_S3, "ERROR signing missing header");
			fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
			return 1;
		}

		size_t header_value_len = strlen(header_value);

		fbr_sha256_update(&crequest, header_value, header_value_len);
		fbr_sha256_update(&crequest, "\n", 1);

		if (header_len == 20 && !strcmp(header_buf, "x-amz-content-sha256")) {
			if (header_value_len >= sizeof(context_hex) || content_hex_len) {
				fbr_rlog(FBR_LOG_CS_S3, "ERROR signing header content");
				fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
				return 1;
			}
			content_hex_len = fbr_strbcpy(context_hex, header_value);
		} else if (header_len == 10 && !strcmp(header_buf, "x-amz-date")) {
			if (header_value_len >= sizeof(timestamp) || timestamp_len) {
				fbr_rlog(FBR_LOG_CS_S3, "ERROR signing header date");
				fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
				return 1;
			}

			timestamp_len = fbr_strbcpy(timestamp, header_value);
		}

		header = next;
	}

	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, headers, headers_len);
	fbr_sha256_update(&crequest, "\n", 1);
	fbr_sha256_update(&crequest, context_hex, content_hex_len);

	char crequest_hex[FBR_HEX_LEN(sizeof(crequest_hash))];
	fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));
	fbr_bin2hex(crequest_hash, sizeof(crequest_hash), crequest_hex, sizeof(crequest_hex));

	// Signature
	char sig_gen[FBR_HEX_LEN(FBR_SHA256_DIGEST_SIZE)];
	struct fbr_cstore_s3 *s3 = &cstore->s3;
	_s3_signature(s3->secret_key, date, date_len, timestamp, crequest_hex, region, region_len,
		scope, scope_len, sig_gen, sizeof(sig_gen));

	if (signature_len != sizeof(sig_gen) - 1 ||  strncmp(sig_gen, signature, signature_len)) {
		fbr_rlog(FBR_LOG_CS_S3, "ERROR sig_gen mismatch (%s)", sig_gen);
		return 1;
	}

	fbr_rlog(FBR_LOG_CS_S3, "Authorization passed");

	return 0;
}
