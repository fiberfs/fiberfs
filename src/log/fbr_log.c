/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <fcntl.h>
#include <sys/mman.h>
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
	assert(log);

	fbr_ZERO(log);

	log->magic = FBR_LOG_MAGIC;
	log->shm_fd = -1;
}

static void
_log_shared_init(struct fbr_log *log, const char *name)
{
	fbr_log_ok(log);
	assert(log->shm_fd == -1);
	assert_zero(log->mmap_ptr);
	assert_zero(*log->shm_name);
	assert(name && *name);

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
}

void
fbr_log_open(const char *name)
{
	assert_zero(_LOG);

	_LOG = malloc(sizeof(*_LOG));
	assert(_LOG);

	_log_init(_LOG);
	_log_ok();

	_log_shared_init(_LOG, name);
}

void
fbr_log_close(void)
{
	_log_ok();
	assert(_LOG->shm_fd >= 0);
	assert(*_LOG->shm_name);
	assert(_LOG->mmap_ptr);

	int ret = close(_LOG->shm_fd);
	assert_zero(ret);

	ret = shm_unlink(_LOG->shm_name);
	assert_zero(ret);

	ret = munmap(_LOG->mmap_ptr, _LOG->mmap_size);
	assert_zero(ret);

	fbr_ZERO(_LOG);
	free(_LOG);

	_LOG = NULL;
}
