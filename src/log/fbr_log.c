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

	pt_assert(pthread_mutex_init(&log->writer.log_lock, NULL));
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
	header->magic = FBR_LOG_HEADER_MAGIC;
	header->version = FBR_LOG_VERSION;
	header->time_created = log->writer.time_created;

	header->segments = FBR_LOG_SEGMENTS;
	header->segment_size = (size - sizeof(struct fbr_log_header)) /
		(sizeof(*header->data) * FBR_LOG_SEGMENTS);
	assert(header->segment_size >= (1024 * 8));

	log->writer.log_pos = header->data;
	log->writer.log_end = header->data + (header->segment_size * FBR_LOG_SEGMENTS);

	*log->writer.log_pos = fbr_log_tag_gen(0, FBR_LOG_TAG_EOF, FBR_LOG_TAG_EOF_DATA, 0);

	fbr_memory_sync();
}

struct fbr_log_header *
fbr_log_header(struct fbr_log *log, void *data, size_t size)
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
_log_shared_init(struct fbr_log *log, const char *name)
{
	assert_dev(log);
	assert_dev(log->shm_fd == -1);
	assert_zero_dev(log->mmap_ptr);
	assert_zero_dev(*log->shm_name);
	assert_dev(name && *name);

	_log_writer_init(log);

	int ret = snprintf(log->shm_name, sizeof(log->shm_name), "/fiberfs:%s", name);
	assert(ret > 0 && (size_t)ret < sizeof(log->shm_name));

	for (size_t i = 1; log->shm_name[i]; i++) {
		if (log->shm_name[i] == '/') {
			log->shm_name[i] = '_';
		}
	}

	log->shm_fd = shm_open(log->shm_name, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	assert(log->shm_fd >= 0);

	// TODO make this configurable
	log->mmap_size = 8 * 1024 * 1024;
	ret = ftruncate(log->shm_fd, log->mmap_size);
	assert_zero(ret);

	log->mmap_ptr = mmap(NULL, log->mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED,
		log->shm_fd, 0);
	assert(log->mmap_ptr != MAP_FAILED);
	assert(log->mmap_ptr);

	_log_header_init(log, log->mmap_ptr, log->mmap_size);

	log->header = fbr_log_header(log, log->mmap_ptr, log->mmap_size);
}

struct fbr_log *
fbr_log_alloc(const char *name)
{
	assert(name && *name);

	struct fbr_log *log = malloc(sizeof(*log));
	assert(log);

	_log_init(log);
	fbr_log_ok(log);

	_log_shared_init(log, name);

	return log;
}

void
fbr_log_free(struct fbr_log *log)
{
	fbr_log_ok(log);
	assert(log->shm_fd >= 0);
	assert(*log->shm_name);
	assert(log->mmap_ptr);

	int ret = close(log->shm_fd);
	assert_zero(ret);

	ret = shm_unlink(log->shm_name);
	assert_zero(ret);

	ret = munmap(log->mmap_ptr, log->mmap_size);
	assert_zero(ret);

	fbr_ZERO(log);
	free(log);
}

fbr_log_data_t
fbr_log_tag_gen(unsigned char sequence, unsigned char type, unsigned short type_data,
    unsigned short length)
{
	assert(type < __FBR_LOG_TAG_TYPE_END);

	struct fbr_log_tag tag;

	tag.parts.magic = FBR_LOG_TAG_MAGIC;
	tag.parts.sequence = sequence;
	tag.parts.type = type;
	tag.parts.type_data = type_data;
	tag.parts.length = length;

	return tag.value;
}
