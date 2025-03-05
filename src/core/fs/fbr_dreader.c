/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <limits.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/context/fbr_callback.h"
#include "core/fuse/fbr_fuse_lowlevel.h"

struct fbr_dreader *
fbr_dreader_alloc(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_dreader *reader = calloc(1, sizeof(*reader));
	assert(reader);

	reader->magic = FBR_DREADER_MAGIC;
	reader->directory = directory;

	return reader;
}

// NOTE: this releeses a dindex, always call after replying to fuse
void
fbr_dreader_free(struct fbr_fs *fs, struct fbr_dreader *reader)
{
	fbr_fs_ok(fs);
	fbr_dreader_ok(reader);

	fbr_dindex_release(fs, &reader->directory);
	assert_zero_dev(reader->directory);

	fbr_ZERO(reader);

	free(reader);
}

void
fbr_dirbuffer_init(struct fbr_dirbuffer *dbuf, size_t fuse_size)
{
	assert(dbuf);
	assert(fuse_size);

	fbr_ZERO(dbuf);

	dbuf->max = sizeof(dbuf->buffer);
	if (dbuf->max > fuse_size) {
		dbuf->max = fuse_size;
	}

	dbuf->free = dbuf->max;
}

void
fbr_dirbuffer_add(struct fbr_request *request, struct fbr_dirbuffer *dbuf, const char *name,
    struct stat *st)
{
	fbr_request_ok(request);
	assert(dbuf);
	assert_zero(dbuf->full);
	assert_dev(dbuf->pos + dbuf->free == dbuf->max);
	assert(name);
	assert(st);

	size_t write = fuse_add_direntry(request->fuse_req, dbuf->buffer + dbuf->pos,
		dbuf->free, name, st, 1);

	if (write > dbuf->free) {
		dbuf->full = 1;
		return;
	}

	dbuf->pos += write;
	dbuf->free -= write;
}
