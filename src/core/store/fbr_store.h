/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_STORE_H_INCLUDED_
#define _FBR_STORE_H_INCLUDED_

#include "core/fs/fbr_fs.h"

struct fbr_store_callbacks {
	void (*fetch_chunk_f)(struct fbr_fs *fs, const struct fbr_file *file,
		struct fbr_chunk *chunk);
	int (*flush_wbuffer_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffers);
};

#endif /* _FBR_STORE_H_INCLUDED_ */
