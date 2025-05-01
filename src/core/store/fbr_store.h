/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_STORE_H_INCLUDED_
#define _FBR_STORE_H_INCLUDED_

#include "core/fs/fbr_fs.h"

#define FBR_JSON_HEADER				"fiberfs"
#define FBR_JSON_VERSION			1
#define FBR_DEFAULT_BUFFERS			4
#define FBR_DEFAULT_BUFLEN			4096

struct fbr_buffer {
	unsigned int				magic;
#define FBR_BUFFER_MAGIC			0xDB60ECD5

	unsigned int				buffer_free:1;
	unsigned int				do_free:1;

	char					*buffer;
	size_t					buffer_pos;
	size_t					buffer_len;

	struct fbr_buffer			*next;
};

struct fbr_writer {
	unsigned int				magic;
#define FBR_WRITER_MAGIC			0xDE0ACCD3

	struct fbr_buffer			*scratch;
	struct fbr_buffer			*final;

	struct fbr_buffer			buffers[FBR_DEFAULT_BUFFERS];

	size_t					raw_bytes;
	size_t					bytes;

	unsigned int				want_gzip:1;
	unsigned int				is_gzip:1;
};

struct fbr_store_callbacks {
	void (*fetch_chunk_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_chunk *chunk);
	void (*store_wbuffer_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffer);
	int (*flush_wbuffers_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffers);
	int (*store_index_f)(struct fbr_fs *fs, struct fbr_directory *directory,
		struct fbr_writer *writer, struct fbr_directory *previous);
};

int fbr_store_index(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_directory *previous);
size_t fbr_root_json(fbr_id_t version, char *buffer, size_t buffer_len);

void fbr_writer_init(struct fbr_fs *fs, struct fbr_request *request,
	struct fbr_writer *writer, int want_gzip);
void fbr_writer_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer,
	size_t buffer_len);
void fbr_writer_add_ulong(struct fbr_fs *fs, struct fbr_writer *writer, unsigned long value);
void fbr_writer_add_id(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t id);
void fbr_writer_free(struct fbr_fs *fs, struct fbr_writer *writer);
void fbr_writer_debug(struct fbr_fs *fs, struct fbr_writer *writer);

#define fbr_buffer_ok(buffer)		fbr_magic_check(buffer, FBR_BUFFER_MAGIC)
#define fbr_writer_ok(writer)		fbr_magic_check(writer, FBR_WRITER_MAGIC)

#endif /* _FBR_STORE_H_INCLUDED_ */
