/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "fbr_cstore.h"
#include "fbr_cstore_api.h"
#include "core/fs/fbr_fs.h"

void
fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	fbr_hash_t hash = fbr_chash_wbuffer(fs, file, wbuffer);
	(void)hash;

	fbr_ABORT("TODO");
}
