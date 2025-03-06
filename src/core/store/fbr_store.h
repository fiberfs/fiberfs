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
	// TODO this goes away when we have proper logging
	void (*directory_expire_f)(struct fbr_fs *fs, struct fbr_directory *directory,
		struct fbr_directory *new_directory);
};

void fbr_directory_expire(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_directory *new_directory);

#endif /* _FBR_STORE_H_INCLUDED_ */
