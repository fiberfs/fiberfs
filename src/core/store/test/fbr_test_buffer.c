/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

int
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

	char one_buffer[10000];
	memset(one_buffer, '1', sizeof(one_buffer));

	fbr_test_logs("*** writer1");

	struct fbr_fs *fs = fbr_test_fs_alloc();

	struct fbr_writer writer1;
	fbr_writer_init(fs, &writer1, NULL, 0);
	size_t bytes = 0;
	for (size_t i = 0; i < 50; i++) {
		fbr_writer_add(fs, &writer1, one_buffer, sizeof(one_buffer));
		bytes += sizeof(one_buffer);
	}
	fbr_writer_flush(fs, &writer1);
	fbr_writer_debug(fs, &writer1);
	fbr_test_ASSERT(writer1.raw_bytes == bytes, "writer1 bytes mismatch");
	fbr_test_ASSERT(writer1.bytes == bytes, "writer1 bytes mismatch");
	size_t i = 0;
	struct fbr_buffer *output = writer1.output;
	while (output) {
		fbr_buffer_ok(output);
		int ret = _test_memcmp(output->buffer, output->buffer_pos, one_buffer,
			sizeof(one_buffer));
		fbr_test_ERROR(ret, "memcmp failed");
		fbr_test_logs("writer.output.%zu passed", i);
		i++;
		output = output->next;
	}
	fbr_writer_free(fs, &writer1);

	fbr_test_ASSERT(fs->stats.buffers == 7, "buffer mismatch");

	fbr_fs_free(fs);

	fbr_test_logs("*** writer2 (workspace)");

	fs = fbr_test_fuse_mock(ctx);
	fbr_fs_ok(fs);

	fuse_req_t fuse_req = (fuse_req_t)1;
	struct fbr_request *r1 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r1);
	r1->not_fuse = 1;
	fbr_request_take_fuse(r1);

	struct fbr_writer writer2;
	fbr_writer_init(fs, &writer2, r1, 0);
	fbr_writer_debug(fs, &writer2);
	bytes = 0;
	for (size_t i = 0; i < 1; i++) {
		fbr_writer_add(fs, &writer2, one_buffer, sizeof(one_buffer));
		bytes += sizeof(one_buffer);
	}
	fbr_writer_flush(fs, &writer2);
	fbr_writer_debug(fs, &writer2);
	fbr_test_ASSERT(writer2.raw_bytes == bytes, "writer2 raw_bytes mismatch");
	fbr_test_ASSERT(writer2.bytes == bytes, "writer2 bytes mismatch");
	i = 0;
	output = writer2.output;
	while (output) {
		fbr_buffer_ok(output);
		int ret = _test_memcmp(output->buffer, output->buffer_pos, one_buffer,
			sizeof(one_buffer));
		fbr_test_ERROR(ret, "memcmp failed");
		fbr_test_logs("writer.output.%zu passed", i);
		i++;
		output = output->next;
	}
	fbr_writer_free(fs, &writer2);

	fbr_test_ASSERT(fs->stats.buffers == 0, "buffer mismatch");

	fbr_request_free(r1);
	fbr_request_pool_shutdown(fs);
	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "writer_test done");
}
