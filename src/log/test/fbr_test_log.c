/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/fuse/fbr_fuse.h"
#include "core/request/fbr_request.h"
#include "log/fbr_log.h"

#include "test/fbr_test.h"
#include "fbr_test_log_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"

struct fbr_test_log_printer {
	unsigned int				magic;
#define FBR_TEST_LOG_PRINT_MAGIC		0x57A22B5D

	struct fbr_log_reader			reader;
	pthread_t				thread;
	int					thread_running;
	int					thread_exit;
	int					silent;
	size_t					lines;
};

#define fbr_test_log_printer_ok(print)		fbr_magic_check(print, FBR_TEST_LOG_PRINT_MAGIC)

extern size_t _FBR_LOG_DEFAULT_SIZE;

void
fbr_cmd_test_log_size(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 1);

	long size = fbr_test_parse_long(cmd->params[0].value);
	assert(size > 0 && (size_t)size >= __FBR_LOG_DEFAULT_SIZE);

	_FBR_LOG_DEFAULT_SIZE = size;

	assert(fbr_log_default_size() == (size_t)size);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_size: %zu", fbr_log_default_size());
}

static void *
_test_log_printer_thread(void *arg)
{
	struct fbr_test_log_printer *printer = arg;
	fbr_test_log_printer_ok(printer);

	struct fbr_log_reader *reader = &printer->reader;
	fbr_log_reader_ok(reader);

	struct fbr_log_header *header = reader->log.header;
	fbr_log_header_ok(header);

	printer->thread_running = 1;

	fbr_test_logs("### log printer running (%s)", reader->log.shm_name);

	unsigned int sleep_count = 0;

	while (1) {
		char log_buffer[FBR_LOGLINE_MAX_LENGTH];
		struct fbr_log_line *log_line;

		log_line = fbr_log_reader_get(reader, log_buffer, sizeof(log_buffer));

		if (!log_line) {
			if (reader->cursor.status == FBR_LOG_CURSOR_EXIT) {
				break;
			}
			fbr_ASSERT(reader->cursor.status != FBR_LOG_CURSOR_OVERFLOW,
				"### LOG OVERFLOW ###");
			fbr_ASSERT(reader->cursor.status == FBR_LOG_CURSOR_EOF,
				"cursor.status=%d", reader->cursor.status);

			if (printer->thread_exit) {
				break;
			}

			fbr_test_sleep_ms(sleep_count);

			if (sleep_count < 20) {
				sleep_count++;
			}

			continue;
		}

		assert(reader->cursor.status == FBR_LOG_CURSOR_OK);

		printer->lines++;
		sleep_count = 0;

		if (printer->silent) {
			continue;
		}

		double time = log_line->timestamp - header->time_created;
		assert(time >= 0);

		const char *type_str = fbr_log_type_str(reader->cursor.tag.parts.class_data);

		char reqid_str[32];
		fbr_log_reqid_str(log_line->request_id, reqid_str, sizeof(reqid_str));

		printf("#%.3f %s:%s %s\n", time, type_str, reqid_str, log_line->buffer);
	}

	fbr_test_logs("### log printer exit");

	return NULL;
}

static void
_test_printer_finish(struct fbr_test_context *test_ctx)
{
	fbr_test_context_ok(test_ctx);

	struct fbr_test_log_printer *printer = test_ctx->printer;
	fbr_test_log_printer_ok(printer);

	if (printer->thread_running) {
		assert_zero(printer->thread_exit);
		fbr_log_reader_ok(&printer->reader);

		printer->thread_exit = 1;

		pt_assert(pthread_join(printer->thread, NULL));

		fbr_log_reader_free(&printer->reader);
	}

	fbr_ZERO(printer);
	free(printer);
	test_ctx->printer = NULL;
}

void
fbr_test_log_printer_init(struct fbr_test_context *test_ctx, const char *logname)
{
	fbr_test_context_ok(test_ctx);
	assert(logname);

	if (test_ctx->printer) {
		fbr_test_log_printer_ok(test_ctx->printer);
		return;
	}

	struct fbr_test_log_printer *printer = calloc(1, sizeof(*printer));
	assert(printer);
	printer->magic = FBR_TEST_LOG_PRINT_MAGIC;
	fbr_test_log_printer_ok(printer);

	if (fbr_test_can_log(NULL, FBR_LOG_VERBOSE)) {
		fbr_log_reader_init(&printer->reader, logname);

		pt_assert(pthread_create(&printer->thread, NULL, _test_log_printer_thread, printer));

		while (!printer->thread_running) {
			fbr_test_sleep_ms(1);
		}
	}

	test_ctx->printer = printer;

	fbr_test_register_finish(test_ctx, "printer", _test_printer_finish);
}

void
fbr_test_log_printer_silent(int silent)
{
	struct fbr_test_context *test_ctx = fbr_test_get_ctx();
	fbr_test_context_ok(test_ctx);
	fbr_test_log_printer_ok(test_ctx->printer);

	test_ctx->printer->silent = silent;
}

size_t
fbr_test_log_printer_lines(void)
{
	struct fbr_test_context *test_ctx = fbr_test_get_ctx();
	fbr_test_context_ok(test_ctx);
	fbr_test_log_printer_ok(test_ctx->printer);

	return test_ctx->printer->lines;
}

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
	fbr_test_logs("LOG_LINE->timestamp: %f", log_line->timestamp);
	fbr_test_logs("LOG_LINE->buffer: '%s'", log_line->buffer);

	assert(log_line->length == strlen(log_line->buffer));
}

void
fbr_cmd_test_log_debug(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_test_fuse_get_ctx(ctx);
	fbr_log_ok(fuse_ctx->log);

	_test_log_debug(fuse_ctx->log);
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

	struct fbr_log *log = fbr_log_alloc(logname, fbr_log_default_size());
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(log->writer.valid);

	_test_log_debug(log);

	struct fbr_log_reader reader;
	fbr_log_reader_init(&reader, logname);

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "111");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "TWO TWO TWO");

	_test_log_debug(log);

	char log_buffer[FBR_LOGLINE_MAX_LENGTH];
	struct fbr_log_line *log_line;
	size_t i = 0;
	while ((log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)))) {
		fbr_test_logs("READER log_buffer[%zu]", i);
		_test_logline_debug(log_line);
		i++;
	}

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "33333333333333333333333");

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

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "12345");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "END");

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
	assert(log_line->request_id == FBR_REQID_TEST);
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

	fbr_test_logs("*** exit");

	log = fbr_log_alloc(logname, fbr_log_default_size());
	fbr_log_ok(log);

	fbr_log_reader_init(&reader, logname);

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "one");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "222");

	fbr_log_free(log);

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	assert_zero(strcmp(log_line->buffer, "one"));

	log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	assert_zero(strcmp(log_line->buffer, "222"));

	assert_zero(fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)));
	assert(reader.cursor.status == FBR_LOG_CURSOR_EXIT);

	fbr_log_reader_free(&reader);

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

	struct fbr_log *log = fbr_log_alloc(logname, fbr_log_default_size() + random() % 11111);
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
		unsigned char buffer[2048];
		size_t buffer_len;
		unsigned short data;

		buffer_len = random() % (sizeof(buffer) - sizeof(buffer_len));
		*((size_t*)buffer) = buffer_len;
		buffer_len += sizeof(buffer_len);
		assert(buffer_len <= sizeof(buffer));

		data = random() % (UCHAR_MAX + 1);
		assert(data <= UCHAR_MAX);

		for (size_t j = sizeof(buffer_len); j < buffer_len; j++) {
			buffer[j] = (unsigned char)data;
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
		buffer[i] = (char)('a' + (random() % 26));
	}
	buffer[length] = '\0';
}

void
fbr_cmd_test_log_rlog(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_fuse_context *fuse_ctx = fbr_fuse_get_context();
	fbr_fuse_mounted(fuse_ctx);

	fbr_test_log_printer_silent(1);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** Logging on request");

	struct fbr_request *request = fbr_test_request_mock();
	fbr_request_ok(request);

	fbr_rlog(FBR_LOG_TEST, "TEST 1");
	fbr_rlog(FBR_LOG_TEST, "TEST %d", 2);
	fbr_rlog(FBR_LOG_TEST, "TEST THREE");

	fbr_request_free(request);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** Reader setup");

	struct fbr_log_reader reader;
	fbr_log_reader_init(&reader, fuse_ctx->path);

	char log_buffer[FBR_LOGLINE_MAX_LENGTH];
	struct fbr_log_line *log_line;

	do {
		log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	} while (log_line && reader.cursor.tag.parts.class_data != FBR_LOG_TEST);
	fbr_test_logs("READER[0]");
	_test_logline_debug(log_line);
	assert_zero(strcmp(log_line->buffer, "TEST 1"));

	do {
		log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	} while (log_line && reader.cursor.tag.parts.class_data != FBR_LOG_TEST);
	fbr_test_logs("READER[1]");
	_test_logline_debug(log_line);
	assert_zero(strcmp(log_line->buffer, "TEST 2"));

	do {
		log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer));
	} while (log_line && reader.cursor.tag.parts.class_data != FBR_LOG_TEST);
	fbr_test_logs("READER[2]");
	_test_logline_debug(log_line);
	assert_zero(strcmp(log_line->buffer, "TEST THREE"));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "*** Flush loop");

	struct fbr_request *r2 = fbr_test_request_mock();
	fbr_request_ok(r2);

	char buffer[500];
	size_t i;
	for (i = 0; i < 20; i++) {
		_log_random_string(buffer, sizeof(buffer) - 1);
		assert(strlen(buffer) == sizeof(buffer) - 1);
		fbr_rlog(FBR_LOG_TEST, "%s", buffer);
	}

	i = 0;
	while ((log_line = fbr_log_reader_get(&reader, log_buffer, sizeof(log_buffer)))) {
		if (reader.cursor.tag.parts.class_data != FBR_LOG_TEST) {
			continue;
		}

		size_t len = strlen(log_line->buffer);

		fbr_test_logs("READER log_buffer[%zu]:%zu", i, len);
		assert_zero(log_line->truncated);
		assert(len == sizeof(buffer) - 1);

		i++;
	}
	assert(i == 19);

	fbr_request_free(r2);
	fbr_log_reader_free(&reader);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_rlog passed");
}

void
fbr_cmd_test_log_printer(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	char logname[100];
	int ret = snprintf(logname, sizeof(logname), "/test/printer/%ld/%d", random(), getpid());
	assert(ret > 0 && (size_t)ret < sizeof(logname));

	struct fbr_log *log = fbr_log_alloc(logname, fbr_log_default_size());
	fbr_log_ok(log);

	fbr_test_log_printer_init(ctx, logname);

	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "One!");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "Message two!");
	fbr_log_print(log, FBR_LOG_TEST, FBR_REQID_TEST, "Last message here, bye");

	fbr_log_free(log);

	fbr_test_sleep_ms(50);

	if (fbr_test_can_log(NULL, FBR_LOG_VERBOSE)) {
		assert(fbr_test_log_printer_lines() == 3);
	} else {
		assert_zero(fbr_test_log_printer_lines());
	}

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "test_log_printer passed");
}
