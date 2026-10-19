/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <string.h>

#include "cstore/fbr_cstore_api.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

#include "test/fbr_test.h"

#define _url_parse_ff(url, offset, length)	\
	fbr_cstore_s3_url_parse(url, strlen(url), offset, length)
#define _url_parse(url)				\
	fbr_cstore_s3_url_parse(url, strlen(url), NULL, NULL)
#define _path_init(path, str)			\
	fbr_cstore_path_init(path, str, strlen(str))

void
fbr_cmd_cstore_url_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	enum fbr_cstore_file_type type;
	size_t offset, length;

	type = _url_parse("/");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse("/abc");
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse_ff("/.fiberfs", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

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

	type = _url_parse_ff("/abc.fiberfschunk.6.1", &offset, &length);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert_zero(offset);
	assert_zero(length);

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

	type = _url_parse_ff("/abc/file.abc.123.fiberfschunk.456.0", &offset, &length);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse("/test/안녕하세요.txt.fiberfschunk.17648630080413561840.102400");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse("/test/%EC%95%88%EB%85%95%ED%95%98%EC%84%B8%EC%9A%94.txt"
		".fiberfschunk.17648630080413561840.102400");
	assert(type == FBR_CSTORE_FILE_CHUNK);

	type = _url_parse_ff("/test_dir/SomeFile.txt.fiberfschunk.17828368500534773756.0",
		&offset, &length);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456/789", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid=0&b=6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 6);
	assert(length == 4);

	type = _url_parse_ff("/123/456?.fiberfschunkid=0", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?fiberfschunkid=0&b=6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid=&b=6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid=a&b=6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid0=0&b=6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid=12345&b=67890&l=7654321", &offset, &length);
	assert(type == FBR_CSTORE_FILE_CHUNK);
	assert(offset == 67890);
	assert(length == 7654321);

	type = _url_parse_ff("/123/456?.fiberfschunkid=12345&b=+67890&l=7654321", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid=0&c=6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);
	assert_zero(offset);
	assert_zero(length);

	type = _url_parse_ff("/123/456?.fiberfschunkid=0&b=6&l=4a", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);

	type = _url_parse_ff("/123/456?.fiberfschunkid=0123&b=6a6&l=4", &offset, &length);
	assert(type == FBR_CSTORE_FILE_NONE);

	struct fbr_cstore_path path;
	struct fbr_cstore_url url;

	_path_init(&path, "something/12345");
	fbr_cstore_s3_url(NULL, &path, &url);
	assert_zero(strcmp(url.value, "/something/12345"));

	_path_init(&path, "path/\"123\"/xyz?abc");
	fbr_cstore_s3_url(NULL, &path, &url);
	assert_zero(strcmp(url.value, "/path/%22123%22/xyz%3Fabc"));

	_path_init(&path, "path/\"123\"/xyz?abc?.fiberfsid=123");
	fbr_cstore_s3_url(NULL, &path, &url);
	assert_zero(strcmp(url.value, "/path/%22123%22/xyz%3Fabc?.fiberfsid=123"));

	struct fbr_cstore *cstore = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(cstore);
	fbr_cstore_s3_init(cstore, "127.0.0.1", 80, 0, "some$pfx!_/fs/", "r", "k", "s");
	fbr_cstore_backend_ok(cstore->s3.backend);
	assert(fbr_cstore_backend_enabled(cstore));
	assert(cstore->s3.prefix);

	_path_init(&path, "path/\"123\"/xyz?abc?.fiberfsid=123");
	fbr_cstore_s3_url(cstore, &path, &url);
	assert_zero(strcmp(url.value,
		"/some%24pfx%21_/fs/path/%22123%22/xyz%3Fabc?.fiberfsid=123"));

	cstore = NULL;

	fbr_test_logs("cstore_url_test done");
}
