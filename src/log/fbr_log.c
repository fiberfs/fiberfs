/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_log.h"
#include "core/request/fbr_request.h"

int _FORCE_LOG_TEST;
double _LOG_TEST_START;

static void
_log_init(struct fbr_log *log)
{
	assert_dev(log);

	fbr_ZERO(log);

	log->magic = FBR_LOG_MAGIC;
	log->shm_fd = -1;
}

static void
_log_writer_init(struct fbr_log *log)
{
	assert_dev(log);
	assert_zero_dev(log->writer.valid);

	log->writer.valid = 1;
	log->writer.time_created = fbr_get_time();

	pt_assert(pthread_mutex_init(&log->writer.lock, NULL));
}

static void
_log_header_init(struct fbr_log *log, void *data, size_t size)
{
	assert_dev(log);
	assert_dev(log->writer.valid);
	assert_zero_dev(log->writer.sequence);
	assert_dev(data);
	assert(size > sizeof(struct fbr_log_header));

	struct fbr_log_header *header = data;

	fbr_ZERO(header);

	header->magic = FBR_LOG_HEADER_MAGIC;
	header->version = FBR_LOG_VERSION;
	header->time_created = log->writer.time_created;

	header->segments = FBR_LOG_SEGMENTS;
	header->segment_type_size = (size - sizeof(*header)) /
		(FBR_LOG_TYPE_SIZE * FBR_LOG_SEGMENTS);
	assert(header->segment_type_size * FBR_LOG_TYPE_SIZE >= FBR_LOG_SEGMENT_MIN_SIZE);

	log->writer.log_pos = header->data;
	log->writer.log_end = header->data + (header->segment_type_size * FBR_LOG_SEGMENTS);

	*log->writer.log_pos = fbr_log_tag_gen(0, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);

	fbr_memory_sync();
}

static struct fbr_log_header *
_log_header_get(struct fbr_log *log, void *data, size_t size)
{
	fbr_log_ok(log);
	assert(data);
	assert(size);

	struct fbr_log_header *header = data;
	fbr_log_header_ok(header);
	assert(header->version == FBR_LOG_VERSION);

	return header;
}

static void
_log_shared_name(const char *name, char *buffer, size_t buffer_len)
{
	assert_dev(name && *name);
	assert_dev(buffer);
	assert_dev(buffer_len);

	int ret = snprintf(buffer, buffer_len, "/fiberfs:%s", name);
	assert(ret > 0 && (size_t)ret < buffer_len);

	for (size_t i = 1; buffer[i]; i++) {
		if (buffer[i] == '/') {
			buffer[i] = '_';
		}
	}
}

static void
_log_shared_init(struct fbr_log *log, const char *name, size_t size)
{
	assert_dev(log);
	assert_dev(log->shm_fd == -1);
	assert_zero_dev(log->mmap_ptr);
	assert_zero_dev(*log->shm_name);
	assert_dev(name && *name);

	int shm_flags = O_RDONLY;
	int mmap_flags = PROT_READ;

	if (size) {
		assert_dev(size >= FBR_LOG_SEGMENT_MIN_SIZE * FBR_LOG_SEGMENTS);

		_log_writer_init(log);

		shm_flags = O_CREAT | O_RDWR;
		mmap_flags = PROT_READ | PROT_WRITE;
	}

	_log_shared_name(name, log->shm_name, sizeof(log->shm_name));
	log->shm_fd = shm_open(log->shm_name, shm_flags, S_IRUSR | S_IWUSR);
	assert(log->shm_fd >= 0);

	if (size) {
		log->mmap_size = size;
		int ret = ftruncate(log->shm_fd, (off_t)log->mmap_size);
		assert_zero(ret);
	}

	struct stat st;
	int ret = fstat(log->shm_fd, &st);
	assert_zero(ret);
	assert(st.st_size > 0);

	if (size) {
		assert(log->mmap_size == (size_t)st.st_size);
	} else {
		log->mmap_size = st.st_size;
	}

	log->mmap_ptr = mmap(NULL, log->mmap_size, mmap_flags, MAP_SHARED, log->shm_fd, 0);
	assert(log->mmap_ptr != MAP_FAILED);
	assert(log->mmap_ptr);

	if (size) {
		_log_header_init(log, log->mmap_ptr, log->mmap_size);
	}

	log->header = _log_header_get(log, log->mmap_ptr, log->mmap_size);
}

struct fbr_log *
fbr_log_alloc(const char *name, size_t size)
{
	assert(name && *name);
	assert(size >= FBR_LOG_SEGMENT_MIN_SIZE * FBR_LOG_SEGMENTS);

	struct fbr_log *log = malloc(sizeof(*log));
	assert(log);

	_log_init(log);
	fbr_log_ok(log);

	log->do_free = 1;

	_log_shared_init(log, name, size);

	return log;
}

fbr_log_data_t
fbr_log_tag_gen(unsigned char sequence, enum fbr_log_tag_class class, unsigned short class_data,
    unsigned short length)
{
	assert(class && class < __FBR_LOG_TAG_END);

	struct fbr_log_tag tag;

	tag.parts.magic = FBR_LOG_TAG_MAGIC;
	tag.parts.sequence = sequence;
	tag.parts.class = class;
	tag.parts.class_data = class_data;
	tag.parts.length = length;

	fbr_log_tag_ok(&tag.parts);

	return tag.value;
}

static inline size_t
_log_segment(struct fbr_log_header *header, fbr_log_data_t *log_pos)
{
	assert_dev(header);
	assert_dev(log_pos);

	size_t segment = (log_pos - header->data) / header->segment_type_size;
	assert(segment < header->segments);

	return segment;
}

static fbr_log_data_t *
_log_get(struct fbr_log *log, unsigned short length, unsigned char *sequence, size_t count)
{
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(log->writer.valid);
	assert_dev(length);
	assert_dev(sequence);
	assert_dev(count);

	size_t length_max = log->header->segment_type_size * FBR_LOG_TYPE_SIZE *
		(FBR_LOG_SEGMENTS - 1);
	assert(length < length_max);

	struct fbr_log_header *header = log->header;
	struct fbr_log_writer *writer = &log->writer;
	size_t type_length = FBR_TYPE_LENGTH(length);

	pt_assert(pthread_mutex_lock(&writer->lock));

	assert(writer->time_created == header->time_created);
	assert(writer->log_pos < writer->log_end);

	writer->stat_appends++;

	fbr_log_data_t eof = fbr_log_tag_gen(writer->sequence, FBR_LOG_TAG_EOF,
		FBR_LOG_TAG_EOF_DATA, 0);
	assert(*writer->log_pos == eof);

	*sequence = writer->sequence;
	writer->sequence++;
	count--;

	fbr_log_data_t *next = writer->log_pos + 1 + type_length;
	size_t segment_counter = header->segment_counter;

	if (next >= writer->log_end) {
		// Start wrap
		assert(header->data + 1 + type_length < writer->log_pos);

		segment_counter += FBR_LOG_SEGMENTS - (segment_counter % FBR_LOG_SEGMENTS);
		assert_zero_dev(segment_counter % FBR_LOG_SEGMENTS);

		fbr_log_data_t wrap = fbr_log_tag_gen(*sequence, FBR_LOG_TAG_WRAP,
			FBR_LOG_TAG_WRAP_DATA, 0);

		*sequence = writer->sequence;
		writer->sequence++;

		eof = fbr_log_tag_gen(*sequence, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);

		header->segment_offset[0] = 0;
		*header->data = eof;

		fbr_memory_sync();

		*writer->log_pos = wrap;
		writer->log_pos = header->data;

		header->segment_counter = segment_counter;

		next = writer->log_pos + 1 + type_length;
		assert_dev(next < writer->log_end);

		writer->stat_log_wraps++;

		if (!segment_counter) {
			writer->stat_segment_wraps++;
		}
	}

	writer->sequence += count;

	eof = fbr_log_tag_gen(writer->sequence, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);
	*next = eof;

	fbr_log_data_t *log_data = writer->log_pos;

	size_t segment_counter_next = _log_segment(header, next);
	while (segment_counter_next > (segment_counter % FBR_LOG_SEGMENTS)) {
		segment_counter++;
		header->segment_offset[segment_counter % FBR_LOG_SEGMENTS] = next - header->data;

		if (!segment_counter) {
			writer->stat_segment_wraps++;
		}
	}

	writer->log_pos = next;

	fbr_memory_sync();

	header->segment_counter = segment_counter;

	pt_assert(pthread_mutex_unlock(&writer->lock));

	return log_data;
}

void
fbr_log_append(struct fbr_log *log, enum fbr_log_tag_class class, unsigned short class_data,
    void *buffer, size_t buffer_len)
{
	fbr_log_ok(log);
	assert(class > FBR_LOG_TAG_NOOP && class < __FBR_LOG_TAG_END);
	assert(buffer);
	assert(buffer_len);

	if (class == FBR_LOG_TAG_LOGLINE) {
		fbr_logline_ok((struct fbr_log_line*)buffer);
	}

	unsigned char sequence;
	fbr_log_data_t *data = _log_get(log, buffer_len, &sequence, 1);

	memcpy(data + 1, buffer, buffer_len);

	fbr_memory_sync();

	*data = fbr_log_tag_gen(sequence, class, class_data, buffer_len);
}

void
fbr_log_batch(struct fbr_log *log, void *buffer, size_t buffer_len, size_t count)
{
	fbr_log_ok(log);
	assert(buffer);
	assert(buffer_len > FBR_LOG_TYPE_SIZE);
	assert(count);

	unsigned char sequence;
	fbr_log_data_t *data = _log_get(log, buffer_len, &sequence, count + 1);

	unsigned char noop_seq = sequence;
	fbr_log_data_t *log_pos = buffer;

	while (count) {
		assert((log_pos - (fbr_log_data_t*)buffer) * FBR_LOG_TYPE_SIZE < buffer_len);

		struct fbr_log_tag *tag = (struct fbr_log_tag*)log_pos;
		fbr_log_tag_ok(&tag->parts);

		if (tag->parts.class == FBR_LOG_TAG_LOGLINE) {
			fbr_logline_ok((struct fbr_log_line*)(log_pos + 1));
		}

		sequence++;
		tag->parts.sequence = sequence;

		size_t type_length = FBR_TYPE_LENGTH(tag->parts.length);
		log_pos += 1 + type_length;

		count--;
	}

	log_pos = buffer;

	memcpy(data + 1, log_pos, buffer_len);

	fbr_memory_sync();

	*data = fbr_log_tag_gen(noop_seq, FBR_LOG_TAG_NOOP, 0, 0);
}

void *
fbr_log_read(struct fbr_log *log, struct fbr_log_cursor *cursor)
{
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(cursor);

	if (cursor->status >= FBR_LOG_CURSOR_ERROR) {
		return NULL;
	}

	fbr_memory_sync();

	struct fbr_log_header *header = log->header;
	int init_sequence = 0;

	if (!cursor->log_pos) {
		cursor->segment_counter = header->segment_counter;
		size_t segment = cursor->segment_counter % header->segments;
		cursor->log_pos = header->data + header->segment_offset[segment];

		init_sequence = 1;
	}

	size_t segment_pos = _log_segment(header, cursor->log_pos);
	while (segment_pos > (cursor->segment_counter % FBR_LOG_SEGMENTS)) {
		cursor->segment_counter++;
	}

	size_t distance = header->segment_counter - cursor->segment_counter;
	if (distance > header->segments - 2) {
		cursor->status = FBR_LOG_CURSOR_OVERFLOW;
		return NULL;
	}

	struct fbr_log_tag tag;
	tag.value = *cursor->log_pos;
	fbr_log_tag_ok(&tag.parts);

	if (init_sequence) {
		cursor->sequence = tag.parts.sequence;
	} else {
		assert(tag.parts.sequence == cursor->sequence);
	}

	if (tag.parts.class == FBR_LOG_TAG_WRAP) {
		assert(tag.parts.class_data == FBR_LOG_TAG_WRAP_DATA);

		cursor->sequence++;
		cursor->log_pos = log->header->data;

		tag.value = *cursor->log_pos;
		fbr_log_tag_ok(&tag.parts);
		assert(tag.parts.sequence == cursor->sequence);

		cursor->segment_counter += FBR_LOG_SEGMENTS -
			(cursor->segment_counter % FBR_LOG_SEGMENTS);
		assert_zero_dev(cursor->segment_counter % FBR_LOG_SEGMENTS);
	}

	cursor->tag.value = tag.value;

	if (tag.parts.class == FBR_LOG_TAG_EOF) {
		assert(tag.parts.class_data == FBR_LOG_TAG_EOF_DATA);

		if (header->exit) {
			cursor->status = FBR_LOG_CURSOR_EXIT;
		} else {
			cursor->status = FBR_LOG_CURSOR_EOF;
		}

		return NULL;
	}

	assert(tag.parts.class >= FBR_LOG_TAG_NOOP && tag.parts.class < __FBR_LOG_TAG_END);

	void *log_buffer = cursor->log_pos + 1;

	size_t type_length = FBR_TYPE_LENGTH(tag.parts.length);
	cursor->log_pos += 1 + type_length;
	cursor->sequence++;
	cursor->status = FBR_LOG_CURSOR_OK;

	return log_buffer;
}

static void
_log_close(struct fbr_log *log)
{
	assert_dev(log);
	assert(log->shm_fd >= 0);
	assert(*log->shm_name);
	assert(log->mmap_ptr);

	if (log->writer.valid) {
		fbr_log_header_ok(log->header);
		assert_zero_dev(log->header->exit);
		log->header->exit = 1;
	}

	int ret = close(log->shm_fd);
	assert_zero(ret);

	ret = munmap(log->mmap_ptr, log->mmap_size);
	assert_zero(ret);

	if (log->writer.valid) {
		ret = shm_unlink(log->shm_name);
		assert_zero(ret);

		pt_assert(pthread_mutex_destroy(&log->writer.lock));
	}
}

void
fbr_log_free(struct fbr_log *log)
{
	fbr_log_ok(log);
	assert(log->do_free);

	_log_close(log);

	fbr_ZERO(log);
	free(log);
}

size_t
fbr_log_print_buf(void *buffer, size_t buffer_len, enum fbr_log_type type,
    unsigned long request_id, const char *fmt, va_list ap)
{
	assert(buffer);
	assert(buffer_len > sizeof(struct fbr_log_line));
	assert(type > __FBR_LOG_TYPE_NONE && type < __FBR_LOG_TYPE_END);
	assert(request_id);
	assert(fmt);
	assert(*fmt);

	if (buffer_len > FBR_LOGLINE_MAX_LENGTH) {
		buffer_len = FBR_LOGLINE_MAX_LENGTH;
	}

	struct fbr_log_line *log_line = (struct fbr_log_line*)buffer;
	log_line->magic = FBR_LOGLINE_MAGIC;
	log_line->request_id = request_id;
	log_line->timestamp = fbr_get_time();
	log_line->length = buffer_len - sizeof(*log_line);
	assert_dev(log_line->length <= buffer_len);

	int ret = vsnprintf(log_line->buffer, log_line->length, fmt, ap);
	assert(ret > 0);

	if (ret >= log_line->length) {
		log_line->truncated = 1;
		log_line->length--;
	} else {
		log_line->length = ret;
	}

	size_t line_len = sizeof(*log_line) + log_line->length + 1;
	assert_dev(line_len <= buffer_len);

	return line_len;
}

void
fbr_log_vprint(struct fbr_log *log, enum fbr_log_type type, unsigned long request_id,
    const char *fmt, va_list ap)
{
	fbr_log_ok(log);

	char buffer[FBR_LOGLINE_MAX_LENGTH];
	size_t buffer_len = fbr_log_print_buf(buffer, sizeof(buffer), type, request_id, fmt, ap);

	fbr_log_append(log, FBR_LOG_TAG_LOGLINE, type, buffer, buffer_len);
}

void __fbr_attr_printf(4)
fbr_log_print(struct fbr_log *log, enum fbr_log_type type, unsigned long request_id,
    const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	fbr_log_vprint(log, type, request_id, fmt, ap);

	va_end(ap);
}

void
fbr_log_cursor_init(struct fbr_log_cursor *cursor)
{
	assert(cursor);
	fbr_ZERO(cursor);
}

void
fbr_log_reader_init(struct fbr_log_reader *reader, const char *name)
{
	assert(reader);
	assert(name && *name);

	fbr_ZERO(reader);
	reader->magic = FBR_LOG_READER_MAGIC;

	_log_init(&reader->log);
	_log_shared_init(&reader->log, name, 0);

	fbr_log_reader_ok(reader);
	fbr_log_ok(&reader->log);
	fbr_log_header_ok(reader->log.header);
	assert_zero(reader->log.writer.valid);

	struct fbr_log_header *header = reader->log.header;

	reader->time_created = header->time_created;

	fbr_log_cursor_init(&reader->cursor);
}

struct fbr_log_line *
fbr_log_reader_get(struct fbr_log_reader *reader, void *buffer, size_t buffer_len)
{
	fbr_log_reader_ok(reader);
	fbr_log_ok(&reader->log);
	fbr_log_header_ok(reader->log.header);
	assert(reader->time_created == reader->log.header->time_created);
	assert(buffer);
	assert(buffer_len > sizeof(struct fbr_log_line));

	const struct fbr_log_line *log_line_read;

	do {
		log_line_read = fbr_log_read(&reader->log, &reader->cursor);

		if (reader->cursor.status >= FBR_LOG_CURSOR_EOF) {
			return NULL;
		}
	} while (reader->cursor.tag.parts.class != FBR_LOG_TAG_LOGLINE);

	fbr_logline_ok(log_line_read);

	size_t log_line_len = sizeof(*log_line_read) + log_line_read->length + 1;
	int truncated = 0;

	if (log_line_len > buffer_len) {
		log_line_len = buffer_len;
		truncated = 1;
	}

	memcpy(buffer, log_line_read, log_line_len);
	struct fbr_log_line *log_line = buffer;
	fbr_logline_ok_dev(log_line);

	if (truncated) {
		log_line->length = buffer_len - sizeof(struct fbr_log_line) - 1;
		assert_dev(log_line->length < buffer_len);
		log_line->buffer[log_line->length] = '\0';
		log_line->truncated = 1;
	}

	assert_dev(log_line->length == strlen(log_line->buffer));

	return log_line;
}

void
fbr_log_cursor_close(struct fbr_log_cursor *cursor)
{
	assert(cursor);
	fbr_ZERO(cursor);
}

void
fbr_log_reader_free(struct fbr_log_reader *reader)
{
	fbr_log_reader_ok(reader);
	fbr_log_ok(&reader->log);
	assert_zero_dev(reader->log.do_free);

	fbr_log_cursor_close(&reader->cursor);
	_log_close(&reader->log);
	fbr_ZERO(reader);
}

const char *
fbr_log_type_str(enum fbr_log_type type)
{
	switch (type) {
		case FBR_LOG_TEST:
			return "TEST";
		case FBR_LOG_DEBUG:
			return "DEBUG";
		case FBR_LOG_ERROR:
			return "ERROR";
		case FBR_LOG_FUSE:
			return "FUSE";
		case FBR_LOG_REQUEST:
			return "REQUEST";
		case FBR_LOG_FS:
			return "FS";
		case FBR_LOG_DINDEX:
			return "DINDEX";
		case FBR_LOG_INODE:
			return "INODE";
		case FBR_LOG_DIR_EXP:
			return "DIR_EXP";
		case FBR_LOG_FLUSH:
			return "FLUSH";
		case FBR_LOG_MERGE:
			return "MERGE";
		case FBR_LOG_CHUNK:
			return "CHUNK";
		case FBR_LOG_BODY:
			return "BODY";
		case FBR_LOG_FIO:
			return "FIO";
		case FBR_LOG_WBUFFER:
			return "WBUFFER";
		case FBR_LOG_INDEX:
			return "INDEX";
		case FBR_LOG_OP:
			return "OP";
		case FBR_LOG_OP_READ:
			return "OP_READ";
		case FBR_LOG_OP_DIR:
			return "OP_DIR";
		case FBR_LOG_OP_FLUSH:
			return "OP_FLUSH";
		case FBR_LOG_OP_ATTR:
			return "OP_ATTR";
		case FBR_LOG_OP_FORGET:
			return "OP_FORGET";
		case FBR_LOG_OP_LOOKUP:
			return "OP_LOOKUP";
		case FBR_LOG_OP_MKDIR:
			return "OP_MKDIR";
		case FBR_LOG_OP_OPEN:
			return "OP_OPEN";
		case FBR_LOG_OP_CREATE:
			return "OP_CREATE";
		case FBR_LOG_OP_RELEASE:
			return "OP_RELEASE";
		case FBR_LOG_OP_WRITE:
			return "OP_WRITE";
		case __FBR_LOG_TYPE_NONE:
		case __FBR_LOG_TYPE_END:
			break;
	}

	return "UNKNOWN";
}

void
fbr_log_reqid_str(unsigned long request_id, char *buffer, size_t buffer_len)
{
	assert(buffer);
	assert(buffer_len);

	int ret;

	if (request_id >= FBR_REQUEST_ID_MIN) {
		ret = snprintf(buffer, buffer_len, "%lu", request_id);
		assert_dev(ret > 0 && (size_t)ret < buffer_len);
		return;
	}

	switch (request_id) {
		case FBR_REQID_TEST:
			ret = snprintf(buffer, buffer_len, "%s", "TEST");
			assert_dev(ret > 0 && (size_t)ret < buffer_len);
			return;
		case FBR_REQID_DEBUG:
			ret = snprintf(buffer, buffer_len, "%s", "DEBUG");
			assert_dev(ret > 0 && (size_t)ret < buffer_len);
			return;
		case FBR_REQID_CORE:
			ret = snprintf(buffer, buffer_len, "%s", "CORE");
			assert_dev(ret > 0 && (size_t)ret < buffer_len);
			return;
		case FBR_REQID_NONE:
		case __FBR_REQID_MAX:
			break;
	}

	ret = snprintf(buffer, buffer_len, "%s", "UNKNOWN");
	assert_dev(ret > 0 && (size_t)ret < buffer_len);
	return;
}

void
fbr_log_test_init(void)
{
	assert(fbr_is_test());
	assert_zero(_LOG_TEST_START);
	_LOG_TEST_START = fbr_get_time();
}

double
fbr_log_test_time(void)
{
	assert(fbr_is_test());
	assert(_LOG_TEST_START);

	double now = fbr_get_time();
	assert(now >= _LOG_TEST_START);

	now -= _LOG_TEST_START;

	return now;
}
