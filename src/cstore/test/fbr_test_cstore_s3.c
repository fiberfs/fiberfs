/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <string.h>

#include "fiberfs.h"
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
	fbr_test_ERROR_param_count(cmd, 2);

	const char *s3_path = cmd->params[0].value;
	long size = fbr_test_parse_long(cmd->params[1].value);
	assert(size > 0);

	fbr_test_logs("cstore_s3_upload done: '%s' bytes: %zu", s3_path, size);
}
