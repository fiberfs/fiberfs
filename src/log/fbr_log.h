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

typedef uint64_t fbr_log_data_t;

enum fbr_log_tag_type
{
	FBR_LOG_TAG_NONE = 0,
	FBR_LOG_TAG_EOF,
	FBR_LOG_TAG_WRAP,
	FBR_LOG_TAG_LOGGING,
	__FBR_LOG_TAG_TYPE_END
};

#define FBR_LOG_TAG_EOF_DATA			0x454545
#define FBR_LOG_TAG_WRAP_DATA			0x575757

struct fbr_log_tag_parts
{
	unsigned short				magic;
#define FBR_LOG_TAG_MAGIC			0xC4A9

	unsigned short				length;

	unsigned int				type:8;
	unsigned int				type_data:24;
};

struct fbr_log_tag {
	union {
		fbr_log_data_t			value;
		struct fbr_log_tag_parts	parts;
	};
};

struct fbr_log_header {
	unsigned int				magic;
#define FBR_LOG_HEADER_MAGIC			0xF8F8AAF2

	int					version;
	double					time_created;

	size_t					segments;
	size_t					segment_size;
	size_t					segment_counter;
	size_t					segment_offset[FBR_LOG_SEGMENTS];

	fbr_log_data_t				data[];
};

struct fbr_log_writer {
	int					valid;

	double					time_created;

	pthread_mutex_t				log_lock;

	fbr_log_data_t				*log_end;
	fbr_log_data_t				*log_pos;
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
fbr_log_data_t fbr_log_tag_gen(unsigned int type, unsigned int type_data, unsigned short length);

#define fbr_log_ok(log)				fbr_magic_check(log, FBR_LOG_MAGIC)
#define fbr_log_header_ok(header)		fbr_magic_check(header, FBR_LOG_HEADER_MAGIC)

#endif /* _FBR_LOG_H_INCLUDED_ */
