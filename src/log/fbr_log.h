/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_LOG_H_INCLUDED_
#define _FBR_LOG_H_INCLUDED_

#include <limits.h>
#include <stddef.h>

enum fbr_log_type {
	FBR_LOG_EMPTY = 0
};

struct fbr_log_entry {
	unsigned char				magic;
#define FBR_LOG_ENTRY_MAGIC			0xC7

	unsigned char				block_len;
	unsigned short				type;
	unsigned int				block;
	unsigned long				id;
};

struct fbr_log_header {
	unsigned int				magic;
#define FBR_LOG_HEADER_MAGIC			0xF8F8AAF2

	double					time_created;
	size_t					size;

	size_t					entry_count;
	struct fbr_log_entry			entries[];
};

struct fbr_log_blocks {
	unsigned int				magic;
#define FBR_LOG_BLOCKS_MAGIC			0x317C3826
};

struct fbr_log {
	unsigned int				magic;
#define FBR_LOG_MAGIC				0x496108CB

	char					shm_name[NAME_MAX + 1];

	int					shm_fd;
	size_t					mmap_size;
	void					*mmap_ptr;

	double					time_created;

	size_t					block_size;
	size_t					block_count;
	void					*blocks;
};

struct fbr_log_header *fbr_log_header(struct fbr_log *log, void *data, size_t size);
struct fbr_log *fbr_log_alloc(const char *name);
void fbr_log_init_global(const char *name);
void fbr_log_free(struct fbr_log *log);
void fbr_log_free_global(void);

#define fbr_log_ok(log)				fbr_magic_check(log, FBR_LOG_MAGIC)
#define fbr_log_header_ok(header)		fbr_magic_check(header, FBR_LOG_HEADER_MAGIC)
#define fbr_log_entry_ok(entry)			fbr_magic_check(entry, FBR_LOG_ENTRY_MAGIC)
#define fbr_log_blocks_ok(blocks)		fbr_magic_check(blocks, FBR_LOG_BLOCKS_MAGIC)

#endif /* _FBR_LOG_H_INCLUDED_ */
