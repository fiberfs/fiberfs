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
#define FBR_JSON_DEFAULT_BUFFERS		4
#define FBR_JSON_DEFAULT_BUFLEN			4096

struct fbr_json_buffer {
	unsigned int				magic;
#define FBR_JSON_BUFFER_MAGIC			0xDB60ECD5

	unsigned int				buffer_free:1;
	unsigned int				do_free:1;

	char					*buffer;
	size_t					buffer_pos;
	size_t					buffer_len;

	struct fbr_json_buffer			*next;
};

struct fbr_json_writer {
	struct fbr_json_buffer			*scratch;
	struct fbr_json_buffer			*final;

	struct fbr_json_buffer			buffers[FBR_JSON_DEFAULT_BUFFERS];

	unsigned int				gzipped:1;
};

struct fbr_store_callbacks {
	void (*fetch_chunk_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_chunk *chunk);
	void (*store_wbuffer_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffer);
	int (*flush_wbuffers_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffers);
};

int fbr_store_index(struct fbr_fs *fs, struct fbr_directory *directory);

void fbr_json_writer_init(struct fbr_fs *fs, struct fbr_json_writer *json);
void fbr_json_writer_free(struct fbr_fs *fs, struct fbr_json_writer *json);
void fbr_json_writer_debug(struct fbr_fs *fs, struct fbr_json_writer *json);

#define fbr_json_buffer_ok(jbuf)		fbr_magic_check(jbuf, FBR_JSON_BUFFER_MAGIC)

#endif /* _FBR_STORE_H_INCLUDED_ */
