/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"

static char _ONE_BUFFER[10000];
static int _INIT;

static void
_test_init(void)
{
	if (_INIT) {
		return;
	}

	_INIT = 1;

	memset(_ONE_BUFFER, '1', sizeof(_ONE_BUFFER));
}

static int
_test_memcmp(char *buffer, size_t buffer_len, char *check, size_t check_len)
{
	assert(buffer);
	assert(check);

	int ret;

	if (buffer_len <= check_len) {
		return memcmp(buffer, check, buffer_len);
	}

	ret = memcmp(buffer, check, check_len);
	if (ret) {
		return ret;
	}

	return _test_memcmp(buffer + check_len, buffer_len - check_len, check, check_len);
}

void
fbr_cmd_writer_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_init();

	fbr_test_logs("*** writer1");

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);

	struct fbr_writer writer1;
	fbr_writer_init(fs, &writer1, NULL, 0);
	size_t bytes = 0;
	for (size_t i = 0; i < 50; i++) {
		fbr_writer_add(fs, &writer1, _ONE_BUFFER, sizeof(_ONE_BUFFER));
		bytes += sizeof(_ONE_BUFFER);
	}
	fbr_writer_flush(fs, &writer1);
	fbr_writer_debug(&writer1);
	fbr_test_ASSERT(writer1.raw_bytes == bytes, "writer1 bytes mismatch");
	fbr_test_ASSERT(writer1.bytes == bytes, "writer1 bytes mismatch");
	size_t i = 0;
	struct fbr_buffer *output = writer1.output;
	while (output) {
		fbr_buffer_ok(output);
		int ret = _test_memcmp(output->buffer, output->buffer_pos, _ONE_BUFFER,
			sizeof(_ONE_BUFFER));
		fbr_test_ERROR(ret, "memcmp failed");
		fbr_test_logs("writer.output.%zu passed", i);
		i++;
		output = output->next;
	}
	fbr_writer_free(&writer1);

	fbr_test_ASSERT(fs->stats.buffers == 7, "buffer mismatch");

	fbr_fs_free(fs);

	fbr_test_logs("*** writer2 (workspace)");

	fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);

	struct fbr_request *r1 = fbr_test_request_mock();
	fbr_request_ok(r1);

	struct fbr_writer writer2;
	fbr_writer_init(fs, &writer2, r1, 0);
	fbr_writer_debug(&writer2);
	bytes = 0;
	for (size_t i = 0; i < 1; i++) {
		fbr_writer_add(fs, &writer2, _ONE_BUFFER, sizeof(_ONE_BUFFER));
		bytes += sizeof(_ONE_BUFFER);
	}
	fbr_writer_flush(fs, &writer2);
	fbr_writer_debug(&writer2);
	fbr_test_ASSERT(writer2.raw_bytes == bytes, "writer2 raw_bytes mismatch");
	fbr_test_ASSERT(writer2.bytes == bytes, "writer2 bytes mismatch");
	i = 0;
	output = writer2.output;
	while (output) {
		fbr_buffer_ok(output);
		int ret = _test_memcmp(output->buffer, output->buffer_pos, _ONE_BUFFER,
			sizeof(_ONE_BUFFER));
		fbr_test_ERROR(ret, "memcmp failed");
		fbr_test_logs("writer.output.%zu passed", i);
		i++;
		output = output->next;
	}
	fbr_writer_free(&writer2);

	fbr_test_ASSERT(fs->stats.buffers == 0, "buffer mismatch");

	fbr_request_free(r1);
	fbr_request_pool_shutdown(fs);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "writer_test done");
}

void
fbr_cmd_reader_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_test_init();

	fbr_test_logs("*** reader1");

	struct fbr_fs *fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);

	struct fbr_reader reader1;
	fbr_reader_init(fs, &reader1, NULL, 0);
	struct fbr_buffer *fbuf = reader1.output;
	assert(fbuf->buffer_len <= sizeof(_ONE_BUFFER));
	fbr_buffer_append(fbuf, _ONE_BUFFER, fbuf->buffer_len);
	int ret = memcmp(fbuf->buffer, _ONE_BUFFER, fbuf->buffer_pos);
	fbr_test_ERROR(ret, "memcmp failed");
	fbr_test_logs("reader passed");
	fbr_reader_free(fs, &reader1);

	fbr_test_ASSERT(fs->stats.buffers == 1, "buffer mismatch");

	fbr_fs_free(fs);

	fbr_test_logs("*** reader2");

	fs = fbr_test_fuse_mock_fs(ctx);
	fbr_fs_ok(fs);

	struct fbr_request *r1 = fbr_test_request_mock();
	fbr_request_ok(r1);

	struct fbr_reader reader2;
	fbr_reader_init(fs, &reader2, r1, 0);
	fbuf = reader2.output;
	assert(fbuf->buffer_len <= sizeof(_ONE_BUFFER));
	fbr_buffer_append(fbuf, _ONE_BUFFER, fbuf->buffer_len);
	ret = memcmp(fbuf->buffer, _ONE_BUFFER, fbuf->buffer_pos);
	fbr_test_ERROR(ret, "memcmp failed");
	fbr_test_logs("reader passed");
	fbr_reader_free(fs, &reader2);

	fbr_test_ASSERT(fs->stats.buffers == 0, "buffer mismatch");

	fbr_request_free(r1);
	fbr_request_pool_shutdown(fs);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "reader_test done");
}
