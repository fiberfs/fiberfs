/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_LOG_H_INCLUDED_
#define _FBR_LOG_H_INCLUDED_

#include <limits.h>
#include <stddef.h>

struct fbr_log_entry {
	unsigned short				type;

	unsigned char				block_len;
	unsigned int				block;

	unsigned long				id;
};

struct fbr_log {
	unsigned int				magic;
#define FBR_LOG_MAGIC				0x496108CB

	char					shm_name[NAME_MAX + 1];

	int					shm_fd;
	size_t					mmap_size;
	void					*mmap_ptr;

	size_t					entry_count;
	struct fbr_log_entry			*entries;

	size_t					block_size;
	size_t					block_len;
	void					*blocks;
};

void fbr_log_open(const char *name);

#define fbr_log_ok(log)				fbr_magic_check(log, FBR_LOG_MAGIC)

#endif /* _FBR_LOG_H_INCLUDED_ */
