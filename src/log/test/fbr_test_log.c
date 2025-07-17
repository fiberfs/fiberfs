/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/request/fbr_request.h"
#include "log/fbr_log.h"
#include "test/fbr_test.h"

extern int _RLOG_TEST;

void
fbr_cmd_test_log_assert(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_logs("FBR_LOG_SEGMENTS=%d", FBR_LOG_SEGMENTS);
	fbr_test_logs("FBR_LOG_VERSION=%d", FBR_LOG_VERSION);
	fbr_test_logs("sizeof(fbr_log_data_t)=%zu", sizeof(fbr_log_data_t));
	fbr_test_logs("sizeof(struct fbr_log_tag_parts)=%zu", sizeof(struct fbr_log_tag_parts));
	fbr_test_logs("sizeof(struct fbr_log_tag)=%zu", sizeof(struct fbr_log_tag));
	fbr_test_logs("__FBR_LOG_TAG_END=%d", __FBR_LOG_TAG_END);
	fbr_test_logs("sizeof(struct fbr_log_line)=%zu", sizeof(struct fbr_log_line));

	assert(sizeof(fbr_log_data_t) == sizeof(struct fbr_log_tag));
	assert(__FBR_LOG_TAG_END <= UCHAR_MAX);

	struct fbr_log_tag tag;
	tag.value = fbr_log_tag_gen(0, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);
	assert(tag.parts.magic == FBR_LOG_TAG_MAGIC);
	assert_zero(tag.parts.sequence);
	assert(tag.parts.class == FBR_LOG_TAG_EOF);
	assert(tag.parts.class_data == FBR_LOG_TAG_EOF_DATA);
	assert_zero(tag.parts.length);

	fbr_test_logs("FBR_LOG_TAG_EOF_DATA=%d", FBR_LOG_TAG_EOF_DATA);
	fbr_test_logs("FBR_LOG_TAG_EOF_DATA='%.2s'", (char*)&tag.parts.class_data);

	tag.value = fbr_log_tag_gen(UCHAR_MAX, FBR_LOG_TAG_WRAP, FBR_LOG_TAG_WRAP_DATA, USHRT_MAX);
	assert(tag.parts.magic == FBR_LOG_TAG_MAGIC);
	assert(tag.parts.sequence == UCHAR_MAX);
	assert(tag.parts.class == FBR_LOG_TAG_WRAP);
	assert(tag.parts.class_data == FBR_LOG_TAG_WRAP_DATA);
	assert(tag.parts.length == USHRT_MAX);

	fbr_test_logs("FBR_LOG_TAG_WRAP_DATA=%d", FBR_LOG_TAG_WRAP_DATA);
	fbr_test_logs("FBR_LOG_TAG_WRAP_DATA='%.2s'", (char*)&tag.parts.class_data);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_assert passed");
}

static void
_test_log_debug(struct fbr_log *log)
{
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);

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

		fbr_test_logs("LOG->writer.stat_appends: %lu", log->writer.stat_appends);
		fbr_test_logs("LOG->writer.stat_log_wraps: %lu", log->writer.stat_log_wraps);
		fbr_test_logs("LOG->writer.stat_segment_wraps: %lu",
			log->writer.stat_segment_wraps);
	}

	if (!log->header) {
		return;
	}

	struct fbr_log_header *header = log->header;
	fbr_log_header_ok(header);

	fbr_test_logs("HEADER->version: %d", header->version);
	fbr_test_logs("HEADER->time_created: %lf", header->time_created);
	fbr_test_logs("HEADER->segments: %zu", header->segments);
	fbr_test_logs("HEADER->segment_type_size: %zu", header->segment_type_size);
	fbr_test_logs("HEADER->segment_counter: %zu", header->segment_counter);

	for (size_t i = 0; i < header->segments; i++) {
		fbr_test_logs("HEADER->segment_offset[%zu]: %zu", i, header->segment_offset[i]);
	}
}

static void
_test_logline_debug(struct fbr_log_line *log_line)
{
	fbr_logline_ok(log_line);

	fbr_test_logs("LOG_LINE->length: %u", log_line->length);
	fbr_test_logs("LOG_LINE->truncated: %u", log_line->truncated);
	fbr_test_logs("LOG_LINE->start: %u", log_line->start);
	fbr_test_logs("LOG_LINE->end: %u", log_line->end);
	fbr_test_logs("LOG_LINE->request_id: %lu", log_line->request_id);
	fbr_test_logs("LOG_LINE->buffer: '%s'", log_line->buffer);

	assert(log_line->length == strlen(log_line->buffer));
}

void
fbr_cmd_test_log_init(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	char logname[100];
	int ret = snprintf(logname, sizeof(logname), "/test/init/%ld/%d", random(), getpid());
	assert(ret > 0 && (size_t)ret < sizeof(logname));

	struct fbr_log *log = fbr_log_alloc(logname, FBR_LOG_DEFAULT_SIZE);
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(log->writer.valid);

	_test_log_debug(log);

	struct fbr_log_reader reader;
	fbr_log_reader_init(&reader, logname);

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQUEST_ID_TEST, "111");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQUEST_ID_TEST, "TWO TWO TWO");

	_test_log_debug(log);

	char log_buffer[FBR_LOGLINE_MAX_LENGTH];
	struct fbr_log_line *log_line;
	size_t i = 0;
	while ((log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)))) {
		fbr_test_logs("READER log_buffer[%zu]", i);
		_test_logline_debug(log_line);
		i++;
	}

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQUEST_ID_TEST, "33333333333333333333333");

	while ((log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)))) {
		fbr_test_logs("READER log_buffer[%zu]", i);
		_test_logline_debug(log_line);
		i++;
	}

	_test_log_debug(log);

	fbr_test_logs("*** writing big[30000]");

	char big[60000];
	char *big_ptr;
	size_t big_size = 30000;
	memset(big, 6, sizeof(big));
	fbr_log_append(log, FBR_LOG_TAG_OTHER, 6, big, big_size);

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQUEST_ID_TEST, "12345");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQUEST_ID_TEST, "END");

	big_ptr = fbr_log_read(&reader.log, &reader.cursor);
	assert(reader.cursor.status == FBR_LOG_CURSOR_OK);
	assert(reader.cursor.tag.parts.class == FBR_LOG_TAG_OTHER);
	assert(reader.cursor.tag.parts.class_data == 6);
	assert(reader.cursor.tag.parts.length == big_size);
	assert_zero(memcmp(big_ptr, big, big_size));

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(*log_line) + 5);
	assert(log_line->truncated);
	assert(log_line->length == 4);
	assert_zero(strcmp(log_line->buffer, "1234"));
	_test_logline_debug(log_line);

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	assert(reader.cursor.tag.parts.class_data == FBR_LOG_TEST);
	assert(log_line->request_id == FBR_REQUEST_ID_TEST);
	assert_zero(log_line->truncated);
	assert_zero(strcmp(log_line->buffer, "END"));
	_test_logline_debug(log_line);

	assert_zero(fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)));
	assert(reader.cursor.status == FBR_LOG_CURSOR_EOF);

	_test_log_debug(log);

	fbr_test_logs("*** overflow");

	big_size = 30000;
	fbr_log_append(log, FBR_LOG_TAG_OTHER, 6, big, big_size);

	fbr_test_logs("*** header.segment_counter: %zu", log->header->segment_counter);
	fbr_test_logs("*** cursor.segment_counter: %zu", reader.cursor.segment_counter);

	big_size = 50000;
	fbr_log_append(log, FBR_LOG_TAG_OTHER, 6, big, big_size);

	_test_log_debug(log);
	fbr_test_logs("*** cursor.segment_counter: %zu", reader.cursor.segment_counter);

	assert_zero(fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)));
	assert(reader.cursor.status == FBR_LOG_CURSOR_OVERFLOW);

	assert(log->writer.stat_appends == 8);

	fbr_log_reader_free(&reader);
	fbr_log_free(log);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_init passed");
}

void
fbr_cmd_test_log_loop(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	char logname[100];
	int ret = snprintf(logname, sizeof(logname), "/test/loop/%ld/%d", random(), getpid());
	assert(ret > 0 && (size_t)ret < sizeof(logname));

	struct fbr_log *log = fbr_log_alloc(logname, FBR_LOG_DEFAULT_SIZE);
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(log->writer.valid);

	assert_zero(log->header->segment_counter);
	log->header->segment_counter -= FBR_LOG_SEGMENTS;

	struct fbr_log_cursor cursor;
	fbr_log_cursor_init(&cursor);

	size_t waiting = 0;
	size_t i;

	for (i = 0; i <= 5000; i++) {
		char buffer[2048];
		size_t buffer_len;
		unsigned short data;

		buffer_len = random() % (sizeof(buffer) - sizeof(buffer_len));
		*((size_t*)buffer) = buffer_len;
		buffer_len += sizeof(buffer_len);
		assert(buffer_len <= sizeof(buffer));

		data = random() % (UCHAR_MAX + 1);
		assert(data <= UCHAR_MAX);

		for (size_t j = sizeof(buffer_len); j < buffer_len; j++) {
			buffer[j] = data;
		}

		fbr_log_append(log, FBR_LOG_TAG_OTHER, data, buffer, buffer_len);

		waiting++;

		if (!i || i == 5000 || random() % 25 == 0 || waiting > 20) {
			char *read_buffer;
			while ((read_buffer = fbr_log_read(log, &cursor))) {
				assert(cursor.status == FBR_LOG_CURSOR_OK);
				size_t read_len = *((size_t*)read_buffer);
				for (size_t j = 0; j < read_len; j++) {
					unsigned char value = read_buffer[sizeof(read_len) + j];
					fbr_ASSERT(value == cursor.tag.parts.class_data,
						"j=%zu len=%zu value=%u expected=%u",
						j, read_len, value, cursor.tag.parts.class_data);
				}
			}
			fbr_ASSERT(cursor.status == FBR_LOG_CURSOR_EOF, "cursor.status: %d",
				cursor.status);

			fbr_test_logs("*** Tests passed %zu (segment_counter: %zu/%zu)", i,
				log->header->segment_counter,
				log->header->segment_counter % FBR_LOG_SEGMENTS);

			waiting = 0;
		}
	}

	_test_log_debug(log);
	assert(cursor.segment_counter == log->header->segment_counter);
	assert(log->writer.stat_log_wraps);
	assert(log->writer.stat_segment_wraps);
	assert(log->writer.stat_appends == i);

	fbr_log_cursor_close(&cursor);
	fbr_log_free(log);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_wrap passed");
}

static void
_log_random_string(char *buffer, size_t length)
{
	for (size_t i = 0; i < length; i++) {
		buffer[i] = 'a';
	}
	buffer[length] = '\0';
}

void
fbr_cmd_test_log_rlog(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_RLOG_TEST = 1;

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	fbr_fuse_mounted(fuse_ctx);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** Logging on request");

	fuse_req_t fuse_req = (fuse_req_t)1;
	struct fbr_request *request = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(request);
	request->not_fuse = 1;
	fbr_request_take_fuse(request);
	fbr_ZERO(&request->thread);

	fbr_rlog(FBR_LOG_TEST, "TEST 1");
	fbr_rlog(FBR_LOG_TEST, "TEST %d", 2);
	fbr_rlog(FBR_LOG_TEST, "TEST THREE");

	fbr_request_free(request);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** Reader setup");

	struct fbr_log_reader reader;
	fbr_log_reader_init(&reader, fuse_ctx->path);

	char log_buffer[FBR_LOGLINE_MAX_LENGTH];
	struct fbr_log_line *log_line;

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	fbr_test_logs("READER[0]");
	_test_logline_debug(log_line);
	assert_zero(strcmp(log_line->buffer, "TEST 1"));

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	fbr_test_logs("READER[1]");
	_test_logline_debug(log_line);
	assert_zero(strcmp(log_line->buffer, "TEST 2"));

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	fbr_test_logs("READER[2]");
	_test_logline_debug(log_line);
	assert_zero(strcmp(log_line->buffer, "TEST THREE"));

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	assert_zero(log_line);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** Flush loop");

	struct fbr_request *r2 = fbr_request_alloc(fuse_req, __func__);
	fbr_request_ok(r2);
	r2->not_fuse = 1;
	fbr_request_take_fuse(r2);
	fbr_ZERO(&r2->thread);

	char buffer[220];
	for (size_t i = 0; i < 20; i++) {
		_log_random_string(buffer, sizeof(buffer) - 1);
		assert(strlen(buffer) == sizeof(buffer) - 1);
		strcpy(buffer, "buffer");
		fbr_rlog(FBR_LOG_TEST, "%s", buffer);
	}

	fbr_request_free(request);

	fbr_log_reader_free(&reader);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_rlog passed");
}
