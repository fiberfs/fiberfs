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

	struct fbr_log_tag tag;
	tag.value = fbr_log_tag_gen(0, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);
	assert(tag.parts.magic == FBR_LOG_TAG_MAGIC);
	assert_zero(tag.parts.sequence);
	assert(tag.parts.type == FBR_LOG_TAG_EOF);
	assert(tag.parts.type_data == FBR_LOG_TAG_EOF_DATA);
	assert_zero(tag.parts.length);

	fbr_test_logs("FBR_LOG_TAG_EOF_DATA=%d", FBR_LOG_TAG_EOF_DATA);
	fbr_test_logs("FBR_LOG_TAG_EOF_DATA='%.2s'", (char*)&tag.parts.type_data);

	tag.value = fbr_log_tag_gen(UCHAR_MAX, FBR_LOG_TAG_WRAP, FBR_LOG_TAG_WRAP_DATA, USHRT_MAX);
	assert(tag.parts.magic == FBR_LOG_TAG_MAGIC);
	assert(tag.parts.sequence == UCHAR_MAX);
	assert(tag.parts.type == FBR_LOG_TAG_WRAP);
	assert(tag.parts.type_data == FBR_LOG_TAG_WRAP_DATA);
	assert(tag.parts.length == USHRT_MAX);

	fbr_test_logs("FBR_LOG_TAG_WRAP_DATA=%d", FBR_LOG_TAG_WRAP_DATA);
	fbr_test_logs("FBR_LOG_TAG_WRAP_DATA='%.2s'", (char*)&tag.parts.type_data);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_assert passed");
}

void
_test_log_debug(struct fbr_log *log)
{
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);

	fbr_test_logs("FBR_LOG_SEGMENTS=%d", FBR_LOG_SEGMENTS);
	fbr_test_logs("FBR_LOG_VERSION=%d", FBR_LOG_VERSION);

	fbr_test_logs("LOG->name: '%s'", log->shm_name);
	fbr_test_logs("LOG->shm_fd: %d", log->shm_fd);
	fbr_test_logs("LOG->mmap_size: %zu", log->mmap_size);
	fbr_test_logs("LOG->mmap_ptr: %p", log->mmap_ptr);

	fbr_test_logs("LOG->writer.valid: %d", log->writer.valid);

	if (log->writer.valid) {
		fbr_test_logs("LOG->writer.time_created: %lf", log->writer.time_created);
		fbr_test_logs("LOG->writer.sequence: %u", log->writer.sequence);
		fbr_test_logs("LOG->writer.log_end: %p (offset: %zu)",
			(void*)log->writer.log_end, log->writer.log_end - log->header->data);
		fbr_test_logs("LOG->writer.log_pos: %p (offset: %zu)",
			(void*)log->writer.log_pos, log->writer.log_pos - log->header->data);
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

	const char *logname = "/test/123";

	struct fbr_log *log = fbr_log_alloc(logname);
	fbr_log_ok(log);
	assert(log->writer.valid);
	assert(log->header);

	_test_log_debug(log);

	struct fbr_log_reader reader;
	fbr_log_reader_init(&reader, logname);

	fbr_log_write(log, "111", 4);
	fbr_log_write(log, "TWO TWO TWO", 12);

	_test_log_debug(log);

	const char *log_buffer;
	size_t i = 0;
	while ((log_buffer = fbr_log_reader_get(&reader))) {
		fbr_test_logs("READER log_buffer[%zu]: '%s'", i, log_buffer);
		i++;
	}

	fbr_log_write(log, "33333333333333333333333", 25);

	while ((log_buffer = fbr_log_reader_get(&reader))) {
		fbr_test_logs("READER log_buffer[%zu]: '%s'", i, log_buffer);
		i++;
	}

	fbr_log_reader_free(&reader);
	fbr_log_free(log);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_init passed");
}
