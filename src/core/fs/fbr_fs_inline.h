/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FS_INLINE_H_INCLUDED_
#define _FBR_FS_INLINE_H_INCLUDED_

#include <stdint.h>

#include "fbr_fs.h"

static inline struct fbr_file *fbr_fh_file(uint64_t fh)
{
	struct fbr_file *file = (struct fbr_file*)fh;
	fbr_file_ok(file);

	return file;
}

static inline struct fbr_directory *fbr_fh_directory(uint64_t fh)
{
	struct fbr_directory *directory = (struct fbr_directory*)fh;
	fbr_directory_ok(directory);

	return directory;
}

#endif /* _FBR_FS_INLINE_H_INCLUDED_ */
