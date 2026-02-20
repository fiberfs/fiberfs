/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_LOG_H_INCLUDED_
#define _FBR_LOG_H_INCLUDED_

#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "fiberfs.h"
#include "fbr_log_types.h"

#define FBR_LOG_SEGMENTS			8
#define FBR_LOG_VERSION				1
#define __FBR_LOG_DEFAULT_SIZE			(65 * 1024UL)
#define FBR_LOG_SEGMENT_MIN_SIZE		(8 * 1024UL)
#define FBR_LOGLINE_MAX_LENGTH			(4 * 1024UL)
#define FBR_LOG_TYPE_SIZE			(sizeof(fbr_log_data_t))
#define FBR_TYPE_LENGTH(len)			(((len) + FBR_LOG_TYPE_SIZE - 1) / \
							FBR_LOG_TYPE_SIZE)

typedef uint64_t fbr_log_data_t;

enum fbr_log_tag_class {
	FBR_LOG_TAG_NONE = 0,
	FBR_LOG_TAG_EOF,
	FBR_LOG_TAG_WRAP,
	FBR_LOG_TAG_NOOP,
	FBR_LOG_TAG_LOGLINE,
	FBR_LOG_TAG_OTHER,
	__FBR_LOG_TAG_END
};

#define FBR_LOG_TAG_EOF_DATA			0x4545
#define FBR_LOG_TAG_WRAP_DATA			0x5757

struct fbr_log_tag_parts {
	unsigned short				magic;
#define FBR_LOG_TAG_MAGIC			0xC4A9

	unsigned char				sequence;

	unsigned char				class;
	unsigned short				class_data;

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
	int					exit;
	double					time_created;

	size_t					segments;
	size_t					segment_type_size;
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

	unsigned long				stat_appends;
	unsigned long				stat_log_wraps;
	unsigned long				stat_segment_wraps;
};

enum fbr_log_cursor_status {
	FBR_LOG_CURSOR_OK = 0,
	FBR_LOG_CURSOR_EOF,
	FBR_LOG_CURSOR_ERROR,
	FBR_LOG_CURSOR_EXIT,
	FBR_LOG_CURSOR_OVERFLOW
};

struct fbr_log_cursor {
	unsigned char				sequence;
	size_t					segment_counter;

	fbr_log_data_t				*log_pos;

	struct fbr_log_tag			tag;
	enum fbr_log_cursor_status		status;
};

struct fbr_log {
	unsigned int				magic;
#define FBR_LOG_MAGIC				0x496108CB

	unsigned int				do_free:1;
	unsigned int				always_flush:1;

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

	struct fbr_log_cursor			cursor;
	struct fbr_log				log;
};

struct fbr_log_line {
	unsigned int				magic;
#define FBR_LOGLINE_MAGIC			0x40E225B8

	unsigned short				length;
	unsigned short				truncated:1;

	unsigned long				request_id;
	double					timestamp;

	char					buffer[];
};

size_t fbr_log_default_size(void);
struct fbr_log *fbr_log_alloc(const char *name, size_t size);
fbr_log_data_t fbr_log_tag_gen(unsigned char sequence, enum fbr_log_tag_class class,
	unsigned short class_data, unsigned short length);
void fbr_log_append(struct fbr_log *log, enum fbr_log_tag_class class,
	unsigned short class_data, void *buffer, size_t buffer_len);
void fbr_log_batch(struct fbr_log *log, void *buffer, size_t buffer_len, size_t count);
void *fbr_log_read(struct fbr_log *log, struct fbr_log_cursor *cursor);
void fbr_log_free(struct fbr_log *log);

size_t fbr_log_print_buf(void *buffer, size_t buffer_len, enum fbr_log_type type,
	unsigned long request_id, const char *fmt, va_list ap);
void fbr_log_vprint(struct fbr_log *log, enum fbr_log_type type, unsigned long request_id,
	const char *fmt, va_list ap);
void __fbr_attr_printf(4) fbr_log_print(struct fbr_log *log, enum fbr_log_type type,
	unsigned long request_id, const char *fmt, ...);

void fbr_log_cursor_init(struct fbr_log_cursor *cursor);
void fbr_log_reader_init(struct fbr_log_reader *reader, const char *name);
struct fbr_log_line *fbr_log_reader_get(struct fbr_log_reader *reader, void *buffer,
	size_t buffer_len);
void fbr_log_cursor_close(struct fbr_log_cursor *cursor);
void fbr_log_reader_free(struct fbr_log_reader *reader);

int fbr_log_type_masked(enum fbr_log_type type);
void fbr_log_reqid_str(unsigned long request_id, char *buffer, size_t buffer_len);

#include "utils/fbr_enum_string_declare.h"
FBR_ENUM_LOG_TYPE

#define fbr_log_ok(log)				fbr_magic_check(log, FBR_LOG_MAGIC)
#define fbr_log_tag_ok(tag)			fbr_magic_check(tag, FBR_LOG_TAG_MAGIC)
#define fbr_log_header_ok(header)		fbr_magic_check(header, FBR_LOG_HEADER_MAGIC)
#define fbr_log_reader_ok(reader)		fbr_magic_check(reader, FBR_LOG_READER_MAGIC)
#define fbr_logline_ok(line)			fbr_magic_check(line, FBR_LOGLINE_MAGIC)
#define fbr_logline_ok_dev(line)		fbr_magic_check_dev(line, FBR_LOGLINE_MAGIC)

#endif /* _FBR_LOG_H_INCLUDED_ */
