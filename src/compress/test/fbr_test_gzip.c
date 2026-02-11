/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "compress/fbr_gzip.h"

#include "test/fbr_test.h"

char *
fbr_var_gzip_enabled(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);

	if (fbr_gzip_enabled()) {
		return "1";
	} else {
		return "0";
	}
}

static void
_gzip_roundtrip(const char *input, size_t input_len)
{
	assert(input);
	assert(input_len);

	struct fbr_gzip compress;
	struct fbr_gzip decompress;
	fbr_gzip_deflate_init(&compress);
	fbr_gzip_inflate_init(&decompress);

	const char *pinput = input;
	size_t pinput_len = input_len;

	char buffer[4096];
	char output[4096];
	size_t written;
	size_t compressed_bytes = 0;
	size_t output_bytes = 0;

	do {
		fbr_gzip_flate(&compress, pinput, pinput_len, buffer, sizeof(buffer), &written, 1);
		assert(compress.status != FBR_GZIP_ERROR);
		assert(written <= sizeof(buffer));

		compressed_bytes += written;

		pinput = NULL;
		pinput_len = 0;

		char *pbuffer = buffer;
		size_t pbuffer_len = written;

		do {
			fbr_gzip_flate(&decompress, pbuffer, pbuffer_len, output, sizeof(output),
				&written, 0);
			assert(decompress.status != FBR_GZIP_ERROR);
			assert(written <= sizeof(output));
			assert_zero(memcmp(input + output_bytes, output, written));

			pbuffer = NULL;
			pbuffer_len = 0;

			output_bytes += written;
			assert(output_bytes <= input_len);
		} while (decompress.status == FBR_GZIP_MORE_BUFFER);
		assert(decompress.status == FBR_GZIP_DONE);
	} while (compress.status == FBR_GZIP_MORE_BUFFER);
	assert(decompress.status == FBR_GZIP_DONE);

	fbr_test_logs("input: %zu compressed: %zu output: %zu", input_len, compressed_bytes,
		output_bytes);
	assert(input_len == output_bytes);

	fbr_gzip_free(&compress);
	fbr_gzip_free(&decompress);
}

void
fbr_cmd_test_gzip(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	assert(ctx);
	fbr_test_ERROR_param_count(cmd, 0);
	assert(fbr_gzip_enabled());

	char buffer[15000];

	fbr_test_logs("*** small string");
	_gzip_roundtrip("FiberFS gzip testing", 20);

	fbr_test_logs("*** random bytes %zu", sizeof(buffer));
	fbr_test_fill_random((uint8_t*)buffer, sizeof(buffer), 0);
	_gzip_roundtrip(buffer, sizeof(buffer));

	fbr_test_logs("*** random ascii bytes %zu", sizeof(buffer));
	fbr_test_fill_random((uint8_t*)buffer, sizeof(buffer), 1);
	_gzip_roundtrip(buffer, sizeof(buffer));

	fbr_test_logs("test_gzip passed");
}
