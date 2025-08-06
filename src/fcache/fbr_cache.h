/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CACHE_H_INCLUDED_
#define _FBR_CACHE_H_INCLUDED_

#include <stdint.h>

#include "core/fs/fbr_fs.h"

typedef uint64_t fbr_chash_t;

void fbr_cache_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);

fbr_chash_t fbr_chash_wbuffer(struct fbr_fs *fs, struct fbr_file *file,
	struct fbr_wbuffer *wbuffer);

#endif /* _FBR_CACHE_H_INCLUDED_ */
