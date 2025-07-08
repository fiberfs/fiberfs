/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_LOG_H_INCLUDED_
#define _FBR_LOG_H_INCLUDED_

#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define FBR_LOG_SEGMENTS			8
#define FBR_LOG_VERSION				1

struct fbr_log_header {
	unsigned int				magic;
#define FBR_LOG_HEADER_MAGIC			0xF8F8AAF2

	int					version;
	double					time_created;

	size_t					segments;
	size_t					segment_size;
	size_t					segment_counter;
	size_t					segment_offset[FBR_LOG_SEGMENTS];

	uint64_t				data[];
};

struct fbr_log_writer {
	int					valid;

	double					time_created;

	pthread_mutex_t				log_lock;

	uint64_t				*log_end;
	uint64_t				*log_pos;
};

struct fbr_log {
	unsigned int				magic;
#define FBR_LOG_MAGIC				0x496108CB

	char					shm_name[NAME_MAX + 1];
	int					shm_fd;
	size_t					mmap_size;
	void					*mmap_ptr;

	struct fbr_log_header			*header;
	struct fbr_log_writer			writer;
};

struct fbr_log_header *fbr_log_header(struct fbr_log *log, void *data, size_t size);
struct fbr_log *fbr_log_alloc(const char *name);
void fbr_log_free(struct fbr_log *log);

#define fbr_log_ok(log)				fbr_magic_check(log, FBR_LOG_MAGIC)
#define fbr_log_header_ok(header)		fbr_magic_check(header, FBR_LOG_HEADER_MAGIC)
#define fbr_log_entry_ok(entry)			fbr_magic_check(entry, FBR_LOG_ENTRY_MAGIC)
#define fbr_log_blocks_ok(blocks)		fbr_magic_check(blocks, FBR_LOG_BLOCKS_MAGIC)

#endif /* _FBR_LOG_H_INCLUDED_ */
