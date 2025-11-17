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

int
fbr_cstore_s3_sign(struct fbr_cstore *cstore, struct chttp_context *http)
{
	fbr_cstore_ok(cstore);
	assert(cstore->s3.backend);
	chttp_context_ok(http);

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

	time_t time_now = (time_t)fbr_get_time();
	struct tm tm_now;
	gmtime_r(&time_now, &tm_now);
	char amz_date[32];
	size_t amz_date_len = strftime(amz_date, sizeof(amz_date), "%Y%m%dT%H%M%SZ", &tm_now);
	assert(amz_date_len);

	const char *amz_content = "UNSIGNED-PAYLOAD";
	size_t amz_content_len = 16;

	fbr_rlog(FBR_LOG_CS_S3, "TODO_SIGN '%.*s':%zu '%.*s':%zu '%s':%zu",
		(int)method_len, method, method_len, (int)url_len, url, url_len,
		amz_date, amz_date_len);

	chttp_header_add(http, "x-amz-date", amz_date);
	chttp_header_add(http, "x-amz-content-sha256", amz_content);

	// Canonical Request
	uint8_t crequest_hash[FBR_SHA256_DIGEST_SIZE];
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
	fbr_sha256_update(&crequest, amz_date, amz_date_len);
	fbr_sha256_update(&crequest, "\n\nhost;x-amz-content-sha256;x-amz-date\n", 39);
	fbr_sha256_update(&crequest, amz_content, amz_content_len);
	fbr_sha256_final(&crequest, crequest_hash, sizeof(crequest_hash));

	return 0;
}
