/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"

#define _url_parse(url)		\
	fbr_cstore_s3_url_parse(url, strlen(url))

void
fbr_cmd_cstore_url_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	enum fbr_cstore_file_type type;

	type = _url_parse("/");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfs");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsRoot");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroot");
	assert(type == FBR_CSTORE_FILE_ROOT);

	type = _url_parse(".fiberfsroot");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroots");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroot.");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroot/abc");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc/.fiberfsroot");
	assert(type == FBR_CSTORE_FILE_ROOT);

	type = _url_parse("/abc/안녕하세요/zzz/.fiberfsroot");
	assert(type == FBR_CSTORE_FILE_ROOT);

	type = _url_parse("/ab?q=/.fiberfsroot");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.1");
	assert(type == FBR_CSTORE_FILE_INDEX);

	type = _url_parse("/.fiberfsindex_1");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc/.fiberfsindex.zzz");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.17648613712223107868");
	assert(type == FBR_CSTORE_FILE_INDEX);

	type = _url_parse("/.fiberfsindex.17648613712.2231078680");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.17648613712223107868");
	assert(type == FBR_CSTORE_FILE_INDEX);

	type = _url_parse("/abc.6.1.fiberfschunk");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.1a");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.a");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.1");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/abc.fiberfschunk.6.11");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/abc.fiberfschunk.62.1");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/abc.fiberfschunk.62.11");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/abc.98");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk..1");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.+00");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunks.6.1");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.-1");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.fiberfschunk.6.a0");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/file.fiberfschunk.abc.0");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc/file.abc.txt.fiberfschunk.123.123456");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/abc/file.abc.123.fiberfschunk.456.0");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/test/안녕하세요.txt.fiberfschunk.17648630080413561840.102400");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/test/%EC%95%88%EB%85%95%ED%95%98%EC%84%B8%EC%9A%94.txt"
		".fiberfschunk.17648630080413561840.102400");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/test_dir/SomeFile.txt.fiberfschunk.17828368500534773756.0");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	fbr_test_logs("cstore_url_test done");
}
