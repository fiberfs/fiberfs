/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <fcntl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_log.h"

fbr_log_data_t fbr_log_tag_gen(unsigned char sequence, enum fbr_log_tag_type type,
	unsigned short type_data, unsigned short length);

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
	header->segment_type_size = (size - sizeof(struct fbr_log_header)) /
		(sizeof(fbr_log_data_t) * FBR_LOG_SEGMENTS);
	assert(header->segment_type_size * sizeof(fbr_log_data_t) >= FBR_LOG_SEGMENT_MIN_SIZE);

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
		int ret = ftruncate(log->shm_fd, log->mmap_size);
		assert_zero(ret);
	} else {
		struct stat st;
		int ret = fstat(log->shm_fd, &st);
		assert_zero(ret);
		assert(st.st_size > 0);

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
fbr_log_tag_gen(unsigned char sequence, enum fbr_log_tag_type type, unsigned short type_data,
    unsigned short length)
{
	assert(type < __FBR_LOG_TAG_TYPE_END);

	struct fbr_log_tag tag;

	tag.parts.magic = FBR_LOG_TAG_MAGIC;
	tag.parts.sequence = sequence;
	tag.parts.type = type;
	tag.parts.type_data = type_data;
	tag.parts.length = length;

	fbr_log_tag_ok(&tag.parts);

	return tag.value;
}

static fbr_log_data_t *
_log_get(struct fbr_log *log, unsigned short length, unsigned char *sequence)
{
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(log->writer.valid);
	assert_dev(length && length <= FBR_LOG_MAX_LENGTH);
	assert_dev(sequence);

	struct fbr_log_header *header = log->header;
	struct fbr_log_writer *writer = &log->writer;
	size_t type_length = (length + sizeof(fbr_log_data_t) - 1) / sizeof(fbr_log_data_t);

	pt_assert(pthread_mutex_lock(&writer->lock));

	assert(writer->log_pos < writer->log_end);

	writer->stat_appends++;

	fbr_log_data_t eof = fbr_log_tag_gen(writer->sequence, FBR_LOG_TAG_EOF,
		FBR_LOG_TAG_EOF_DATA, 0);
	assert(*writer->log_pos == eof);

	*sequence = writer->sequence;
	writer->sequence++;

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

		writer->stat_wraps++;
	}

	eof = fbr_log_tag_gen(writer->sequence, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);
	*next = eof;

	fbr_log_data_t *log_data = writer->log_pos;

	size_t segment_counter_next = (next - header->data) / header->segment_type_size;
	while (segment_counter_next > segment_counter) {
		segment_counter++;
		header->segment_offset[segment_counter % FBR_LOG_SEGMENTS] = next - header->data;
	}

	writer->log_pos = next;

	fbr_memory_sync();

	header->segment_counter = segment_counter;

	pt_assert(pthread_mutex_unlock(&writer->lock));

	return log_data;
}

void
fbr_log_append(struct fbr_log *log, enum fbr_log_tag_type type, unsigned short type_data,
    void *buffer, size_t buffer_len)
{
	fbr_log_ok(log);
	assert(type > FBR_LOG_TAG_NOOP && type < __FBR_LOG_TAG_TYPE_END);
	assert(buffer);
	assert(buffer_len);

	unsigned char sequence;
	fbr_log_data_t *data = _log_get(log, buffer_len, &sequence);

	memcpy(data + 1, buffer, buffer_len);

	fbr_memory_sync();

	*data = fbr_log_tag_gen(sequence, type, type_data, buffer_len);
}

void *
fbr_log_read(struct fbr_log *log, fbr_log_data_t **log_pos, unsigned char *sequence,
    struct fbr_log_tag *tag)
{
	fbr_log_ok(log);
	fbr_log_header_ok(log->header);
	assert(log_pos);
	assert(sequence);
	assert(tag);

	// TODO we need to keep a segment counter here and keep within a safe distance

	fbr_memory_sync();

	int init_sequence = 0;

	if (!*log_pos) {
		struct fbr_log_header *header = log->header;

		size_t segment = header->segment_counter % header->segments;
		*log_pos = header->data + header->segment_offset[segment];

		init_sequence = 1;
	}

	tag->value = **log_pos;
	fbr_log_tag_ok(&tag->parts);

	if (init_sequence) {
		*sequence = tag->parts.sequence;
	} else {
		assert(tag->parts.sequence == *sequence);
	}

	if (tag->parts.type == FBR_LOG_TAG_WRAP) {
		assert(tag->parts.type_data == FBR_LOG_TAG_WRAP_DATA);

		(*sequence)++;
		*log_pos = log->header->data;

		tag->value = **log_pos;
		fbr_log_tag_ok(&tag->parts);
		assert(tag->parts.sequence == *sequence);
	}

	if (tag->parts.type == FBR_LOG_TAG_EOF) {
		assert(tag->parts.type_data == FBR_LOG_TAG_EOF_DATA);
		return NULL;
	}

	assert(tag->parts.type > FBR_LOG_TAG_NOOP && tag->parts.type < __FBR_LOG_TAG_TYPE_END);
	void *log_buffer = *log_pos + 1;

	size_t type_length = (tag->parts.length + sizeof(fbr_log_data_t) - 1) /
		sizeof(fbr_log_data_t);
	*log_pos += 1 + type_length;
	(*sequence)++;

	return log_buffer;
}

void
fbr_log_write(struct fbr_log *log, void *buffer, size_t buffer_len)
{
	fbr_log_ok(log);
	assert(buffer);
	assert(buffer_len);
	assert(buffer_len <= FBR_LOG_MAX_LENGTH);

	// TODO put a header on buffer
	fbr_log_append(log, FBR_LOG_TAG_LOGGING, 0, buffer, buffer_len);
}

static void
_log_close(struct fbr_log *log)
{
	assert_dev(log);
	assert(log->shm_fd >= 0);
	assert(*log->shm_name);
	assert(log->mmap_ptr);

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
	assert(log->do_free)

	fbr_ZERO(log);
	free(log);
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
	reader->log_pos = NULL;
}

const char *
fbr_log_reader_get(struct fbr_log_reader *reader)
{
	fbr_log_reader_ok(reader);
	fbr_log_ok(&reader->log);

	// TODO we need to copy into a buffer and also check for overrrun

	struct fbr_log_tag tag;
	const char *log_buffer = fbr_log_read(&reader->log, &reader->log_pos, &reader->sequence,
		&tag);

	return log_buffer;
}

void
fbr_log_reader_free(struct fbr_log_reader *reader)
{
	fbr_log_reader_ok(reader);
	fbr_log_ok(&reader->log);
	assert_zero_dev(reader->log.do_free);

	_log_close(&reader->log);
	fbr_ZERO(reader);
}
