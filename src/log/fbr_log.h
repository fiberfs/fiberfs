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
#define FBR_LOG_SEGMENT_MIN_SIZE		(8 * 1024)
#define FBR_LOG_MAX_LENGTH			(4 * 1024)

typedef uint64_t fbr_log_data_t;

enum fbr_log_tag_type
{
	FBR_LOG_TAG_NONE = 0,
	FBR_LOG_TAG_EOF,
	FBR_LOG_TAG_WRAP,
	FBR_LOG_TAG_LOGGING,
	__FBR_LOG_TAG_TYPE_END
};

#define FBR_LOG_TAG_EOF_DATA			0x4545
#define FBR_LOG_TAG_WRAP_DATA			0x5757

struct fbr_log_tag_parts {
	unsigned short				magic;
#define FBR_LOG_TAG_MAGIC			0xC4A9

	unsigned char				sequence;

	unsigned char				type;
	unsigned short				type_data;

	unsigned short				length;
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
	unsigned char				sequence;
	pthread_mutex_t				lock;

	fbr_log_data_t				*log_end;
	fbr_log_data_t				*log_pos;
};

struct fbr_log {
	unsigned int				magic;
#define FBR_LOG_MAGIC				0x496108CB

	unsigned int				do_free:1;

	char					shm_name[NAME_MAX + 1];
	int					shm_fd;
	size_t					mmap_size;
	void					*mmap_ptr;

	struct fbr_log_header			*header;
	struct fbr_log_writer			writer;
};

struct fbr_log_reader {
	unsigned int				magic;
#define FBR_LOG_READER_MAGIC			0x5EBC86C6

	double					time_created;
	unsigned char				sequence;
	size_t					segment_pos;
	fbr_log_data_t				*log_pos;

	struct fbr_log				log;
};

struct fbr_log_header *fbr_log_header(struct fbr_log *log, void *data, size_t size);
struct fbr_log *fbr_log_alloc(const char *name);
void fbr_log_free(struct fbr_log *log);
fbr_log_data_t fbr_log_tag_gen(unsigned char sequence, unsigned char type,
	unsigned short type_data, unsigned short length);
void fbr_log_write(struct fbr_log *log, void *buffer, size_t buffer_len);

void fbr_log_reader_init(struct fbr_log_reader *reader, const char *name);
void fbr_log_reader_free(struct fbr_log_reader *reader);
const char *fbr_log_reader_get(struct fbr_log_reader *reader);

#define fbr_log_ok(log)				fbr_magic_check(log, FBR_LOG_MAGIC)
#define fbr_log_tag_ok(tag)			fbr_magic_check(tag, FBR_LOG_TAG_MAGIC)
#define fbr_log_header_ok(header)		fbr_magic_check(header, FBR_LOG_HEADER_MAGIC)
#define fbr_log_reader_ok(reader)		fbr_magic_check(reader, FBR_LOG_READER_MAGIC)

#endif /* _FBR_LOG_H_INCLUDED_ */
