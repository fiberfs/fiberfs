/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_STORE_H_INCLUDED_
#define _FBR_STORE_H_INCLUDED_

#include "core/fs/fbr_fs.h"

#define FBR_JSON_HEADER			"fiberfs"
#define FBR_JSON_VERSION		1

struct fbr_json_buffer {
	char				*buffer;
	size_t				buffer_len;

	struct fbr_json_buffer		*next;

	unsigned int			do_free:1;
};

struct fbr_json_writer {
	struct fbr_json_buffer		*scratch;
	struct fbr_json_buffer		*final;

	unsigned int			gzipped:1;
};

struct fbr_store_callbacks {
	void (*fetch_chunk_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_chunk *chunk);
	void (*store_wbuffer_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffer);
	int (*flush_wbuffers_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffers);
};

int fbr_store_index(void);

#endif /* _FBR_STORE_H_INCLUDED_ */
