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

struct fbr_log *_LOG;

#define _log_ok()		fbr_log_ok(_LOG)

static void
_log_init(struct fbr_log *log)
{
	assert_dev(log);

	fbr_ZERO(log);

	log->magic = FBR_LOG_MAGIC;
	log->shm_fd = -1;
	log->time_created = fbr_get_time();
}

static void
_log_data_init(struct fbr_log *log, void *data, size_t size)
{
	assert_dev(log);
	assert_dev(data);
	assert(size > sizeof(struct fbr_log_header));

	struct fbr_log_header *header = data;
	header->magic = FBR_LOG_HEADER_MAGIC;
	header->time_created = log->time_created;
	header->size = size;

	// TODO make configurable
	log->block_size = 64;
	header->entry_count = size / log->block_size;
	assert(header->entry_count > 16);

	for (size_t i = 0; i < header->entry_count; i++) {
		struct fbr_log_entry *entry = &header->entries[i];
		entry->magic = FBR_LOG_ENTRY_MAGIC;
		entry->type = FBR_LOG_EMPTY;
	}

	struct fbr_log_blocks *blocks =
		(struct fbr_log_blocks*)&header->entries[header->entry_count];
	blocks->magic = FBR_LOG_BLOCKS_MAGIC;

	log->blocks = blocks + 1;
	size_t header_size = (uintptr_t)log->blocks - (uintptr_t)data;
	assert(size > header_size);
	log->block_count = (size - header_size) / log->block_size;
	assert(log->block_count >= 16);
}

struct fbr_log_header *
fbr_log_header(struct fbr_log *log, void *data, size_t size)
{
	fbr_log_ok(log);
	assert(data);

	struct fbr_log_header *header = data;
	fbr_log_header_ok(header);
	assert(header->size == size);
	assert(header->time_created == log->time_created);
	assert(header->entry_count);

	if (fbr_assert_is_dev()) {
		for (size_t i = 0; i < header->entry_count; i++) {
			struct fbr_log_entry *entry = &header->entries[i];
			fbr_log_entry_ok(entry);
		}
	}

	struct fbr_log_blocks *blocks =
		(struct fbr_log_blocks*)&header->entries[header->entry_count];
	fbr_log_blocks_ok(blocks);
	assert((uintptr_t)log->blocks == (uintptr_t)blocks + sizeof(*blocks));

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

	_log_data_init(log, log->mmap_ptr, log->mmap_size);
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
fbr_log_init_global(const char *name)
{
	assert_zero(_LOG);

	_LOG = fbr_log_alloc(name);
	_log_ok();
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

void
fbr_log_free_global(void)
{
	_log_ok();

	fbr_log_free(_LOG);
	_LOG = NULL;
}
