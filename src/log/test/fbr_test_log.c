/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "log/fbr_log.h"
#include "test/fbr_test.h"

void
fbr_cmd_test_log_assert(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("sizeof(fbr_log_data_t)=%zu", sizeof(fbr_log_data_t));
	fbr_test_logs("sizeof(struct fbr_log_tag_parts)=%zu", sizeof(struct fbr_log_tag_parts));
	fbr_test_logs("sizeof(struct fbr_log_tag)=%zu", sizeof(struct fbr_log_tag));

	assert(sizeof(fbr_log_data_t) == sizeof(struct fbr_log_tag));

	fbr_test_logs("FBR_LOG_TAG_EOF_DATA=%d", FBR_LOG_TAG_EOF_DATA);
	fbr_test_logs("FBR_LOG_TAG_WRAP_DATA=%d", FBR_LOG_TAG_WRAP_DATA);

	struct fbr_log_tag tag;
	tag.value = fbr_log_tag_gen(FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);
	assert(tag.parts.magic == FBR_LOG_TAG_MAGIC);
	assert_zero(tag.parts.length);
	assert(tag.parts.type == FBR_LOG_TAG_EOF);
	assert(tag.parts.type_data == FBR_LOG_TAG_EOF_DATA);

	tag.value = fbr_log_tag_gen(FBR_LOG_TAG_WRAP, FBR_LOG_TAG_WRAP_DATA, USHRT_MAX);
	assert(tag.parts.magic == FBR_LOG_TAG_MAGIC);
	assert(tag.parts.length == USHRT_MAX);
	assert(tag.parts.type == FBR_LOG_TAG_WRAP);
	assert(tag.parts.type_data == FBR_LOG_TAG_WRAP_DATA);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_assert passed");
}

void
_test_log_debug(struct fbr_log *log)
{
	fbr_log_ok(log);

	fbr_test_logs("FBR_LOG_SEGMENTS=%d", FBR_LOG_SEGMENTS);
	fbr_test_logs("FBR_LOG_VERSION=%d", FBR_LOG_VERSION);

	fbr_test_logs("LOG->name: '%s'", log->shm_name);
	fbr_test_logs("LOG->shm_fd: %d", log->shm_fd);
	fbr_test_logs("LOG->mmap_size: %zu", log->mmap_size);
	fbr_test_logs("LOG->mmap_ptr: %p", log->mmap_ptr);

	fbr_test_logs("LOG->writer.valid: %d", log->writer.valid);

	if (log->writer.valid) {
		fbr_test_logs("LOG->writer.time_created: %lf", log->writer.time_created);
		fbr_test_logs("LOG->writer.log_end: %p", (void*)log->writer.log_end);
		fbr_test_logs("LOG->writer.log_pos: %p", (void*)log->writer.log_pos);
	}

	if (!log->header) {
		return;
	}

	struct fbr_log_header *header = log->header;
	fbr_log_header_ok(header);

	fbr_test_logs("HEADER->version: %d", header->version);
	fbr_test_logs("HEADER->time_created: %lf", header->time_created);
	fbr_test_logs("HEADER->segments: %zu", header->segments);
	fbr_test_logs("HEADER->segment_size: %zu", header->segment_size);
	fbr_test_logs("HEADER->segment_counter: %zu", header->segment_counter);

	for (size_t i = 0; i < header->segments; i++) {
		fbr_test_logs("HEADER->segment_offset[%zu]: %zu", i, header->segment_offset[i]);
	}
}

void
fbr_cmd_test_log_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_log *log = fbr_log_alloc("/test/123");
	fbr_log_ok(log);
	assert(log->writer.valid);
	assert(log->header);

	_test_log_debug(log);

	fbr_log_data_t eof = fbr_log_tag_gen(FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);
	assert(*log->writer.log_pos == eof);

	fbr_log_free(log);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_init passed");
}
