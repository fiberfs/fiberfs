/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>

#include "fiberfs.h"
#include "fbr_iocmd.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/request/fbr_rlog.h"

int
fbr_iocmd_merge(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
   const void *input, void *output)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(command == FBR_IOCMD_MERGE_REQ);
	assert(input);
	assert_zero(output);

	const struct fbr_iocmd_merge *io_merge = input;

	if (!fbr_object_is_valid(io_merge, FBR_IOCMD_MERGE_MAGIC)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR magic");
		return EIO;
	} else if (!fbr_file_is_file(file)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR not file");
		return EINVAL;
	}

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_rlog(FBR_LOG_IOCMD_MERGE, "file: '%s'", filename.name);

	return 0;
}
