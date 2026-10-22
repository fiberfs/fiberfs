/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <string.h>

#include "fiberfs.h"
#include "chttp.h"
#include "cstore/fbr_cstore_api.h"
#include "cstore/s3/fbr_cstore_s3.h"
#include "cstore/test/fbr_test_cstore_cmds.h"
#include "utils/fbr_chash.h"

#include "test/fbr_test.h"

static char _TEST_S3_UPLOAD_MD5[FBR_HEX_LEN(FBR_MD5_DIGEST_SIZE)];

const char *
fbr_var_cstore_s3_md5(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert(strlen(_TEST_S3_UPLOAD_MD5) == sizeof(_TEST_S3_UPLOAD_MD5) - 1);

	return _TEST_S3_UPLOAD_MD5;
}

void
fbr_cmd_cstore_s3_upload(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ok(ctx->test);
	fbr_test_ERROR_param_count(cmd, 2);

	struct fbr_cstore_path filepath;
	fbr_cstore_path_init(&filepath, cmd->params[0].value, cmd->params[0].len);

	long size = fbr_test_parse_long(cmd->params[1].value);
	assert(size > 0);

	struct fbr_cstore *cstore = fbr_test_cstore_get(ctx, 0);
	fbr_cstore_ok(cstore);
	fbr_cstore_backend_ok(cstore->s3.backend);

	char chttp_stack[FBR_CSTORE_CHTTP_SIZE];
	struct chttp_context *http = chttp_context_init_buf(chttp_stack, sizeof(chttp_stack));
	chttp_context_ok(http);

	struct fbr_cstore_url url;
	fbr_cstore_s3_url(cstore, &filepath, &url);

	fbr_test_logs("  * s3_upload url: '%s'", url.value);

	url.length += fbr_snaprintf(url.value, sizeof(url.value), url.length,
		"?%s=%d&b=%d&l=%ld",
		FBR_FIBERFS_CHUNKID_NAME, 420, 0, size);

	chttp_set_method(http, "PUT");
	chttp_set_url(http, url.value);

	struct fbr_cstore_backend *s3_backend = cstore->s3.backend;
	assert(s3_backend->host);
	chttp_header_add(http, "Host", s3_backend->host);

	char buffer[32];
	fbr_bprintf(buffer, "%zu", size);
	chttp_header_add(http, "Content-Length", buffer);
	chttp_header_add(http, "If-None-Match", "*");

	fbr_cstore_s3_autosign(cstore, http, NULL, NULL);

	chttp_connect(http, s3_backend->host, s3_backend->host_len, s3_backend->port,
		s3_backend->tls);
	chttp_addr_resolved(&http->addr);

	chttp_send(http);
	assert(http->state == CHTTP_STATE_SENT);
	assert(http->length == size);

	struct fbr_md5_ctx md5;
	fbr_md5_init(&md5);

	while (http->length > 0) {
		uint8_t buffer[1024];
		size_t buffer_len = http->length;
		if (buffer_len > sizeof(buffer)) {
			buffer_len = sizeof(buffer);
		}

		fbr_test_fill_random(buffer, buffer_len, 0);
		chttp_body_send(http, buffer, buffer_len);
		fbr_md5_update(&md5, buffer, buffer_len);
	}

	fbr_test_logs("  * s3_upload bytes sent: %ld", size);

	chttp_receive(http);
	assert(http->state == CHTTP_STATE_IDLE);
	assert_zero(http->length);
	assert_zero(http->error);

	fbr_test_logs("  * s3_upload resp status: %d", http->status);

	if (ctx->test->verbocity >= FBR_LOG_VERBOSE) {
		chttp_context_debug(http);
	}

	assert(http->status == 200);

	fbr_md5_final(&md5);
	fbr_bin2hex(md5.digest, sizeof(md5.digest), _TEST_S3_UPLOAD_MD5,
		sizeof(_TEST_S3_UPLOAD_MD5));

	chttp_context_free(http);

	fbr_test_logs("cstore_s3_upload done: '%s' bytes: %zu", filepath.value, size);
}
