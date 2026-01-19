/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"

#define _url_parse(url, etag, offset)	\
	fbr_cstore_url_parse(url, sizeof(url) - 1, etag, sizeof(etag) - 1, offset)

void
fbr_cmd_cstore_url_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	size_t offset;
	enum fbr_cstore_entry_type type;

	type = _url_parse("/", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);

	type = _url_parse("/abc", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfs", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsRoot", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroot", "", &offset);
	assert(type == FBR_CSTORE_FILE_ROOT);
	assert_zero(offset);

	type = _url_parse(".fiberfsroot", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroots", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroot.", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsroot/abc", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc/.fiberfsroot", "", &offset);
	assert(type == FBR_CSTORE_FILE_ROOT);
	assert_zero(offset);

	type = _url_parse("/abc/안녕하세요/zzz/.fiberfsroot", "", &offset);
	assert(type == FBR_CSTORE_FILE_ROOT);

	type = _url_parse("/ab?q=/.fiberfsroot", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.", "", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.1", "1", &offset);
	assert(type == FBR_CSTORE_FILE_INDEX);
	assert_zero(offset);

	type = _url_parse("/.fiberfsindex_1", "1", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc/.fiberfsindex.zzz", "zzz", &offset);
	assert(type == FBR_CSTORE_FILE_INDEX);

	type = _url_parse("/.fiberfsindex.17648613712223107868", "17648613712223107868", &offset);
	assert(type == FBR_CSTORE_FILE_INDEX);
	assert_zero(offset);

	type = _url_parse("/.fiberfsindex.176486137122231078680", "17648613712223107868", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/.fiberfsindex.17648613712223107868", "176486137122231078680", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.1.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 1);

	type = _url_parse("/abc.62.1.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.98", "987654321", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.1.fiberfschunk", "63", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.1a.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.00.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.1.fiberfschunks", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.-1.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6.a0.fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc.6..fiberfschunk", "6", &offset);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/file.abc.0.fiberfschunk", "abc", &offset);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 0);

	type = _url_parse("/abc/file.abc.txt.abc.123456.fiberfschunk", "abc", &offset);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 123456);

	type = _url_parse("/abc/file.abc.123.abc.444.fiberfschunk", "abc", &offset);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 444);

	type = _url_parse("/test/안녕하세요.txt.17648630080413561840.102400.fiberfschunk",
		"17648630080413561840", &offset);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 102400);

	type = _url_parse("/test/%EC%95%88%EB%85%95%ED%95%98%EC%84%B8%EC%9A%94.txt"
		".17648630080413561840.102400.fiberfschunk",
		"17648630080413561840", &offset);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 102400);

	fbr_test_logs("cstore_url_test done");
}
