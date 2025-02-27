/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"

struct fbr_freader *
fbr_freader_alloc(struct fbr_fs *fs, struct fbr_file *file)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);

	struct fbr_freader *reader = calloc(1, sizeof(*reader));
	assert(reader);

	reader->magic = FBR_FREADER_MAGIC;
	reader->file = file;

	return reader;
}

void
fbr_freader_free(struct fbr_fs *fs, struct fbr_freader *reader)
{
	fbr_fs_ok(fs);
	fbr_freader_ok(reader);

	fbr_inode_release(fs, &reader->file);
	assert_zero_dev(reader->file);

	fbr_ZERO(reader);

	free(reader);
}
