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
#include "cstore/fbr_cstore_api.h"
#include "cstore/s3/fbr_cstore_s3.h"

int
fbr_iocmd_merge(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
   const void *input, void *output)
{
	fbr_fs_ok(fs);
	assert(fs->store);
	fbr_file_ok(file);
	assert(command == FBR_IOCMD_MERGE_REQ);
	assert(input);
	assert_zero(output);

	const struct fbr_iocmd_merge *io_merge = input;

	// TODO
	// We need to pull the latest directory
	// and move this into a flush_cmd so we are atomic on upload

	if (!fbr_object_is_valid(io_merge, FBR_IOCMD_MERGE_MAGIC)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR magic");
		return EIO;
	} else if (!fbr_file_is_file(file)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR not file");
		return EINVAL;
	} else if (!fs->cstore || !fbr_cstore_backend_enabled(fs->cstore)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR cstore");
		return EIO;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_rlog(FBR_LOG_IOCMD_MERGE, "file: '%s'", filename.name);

	size_t file_size = file->size;
	int has_chunk = 0;
	int is_external = 0;

	struct fbr_chunk *chunk = file->body.chunks;
	while (chunk) {
		fbr_chunk_ok(chunk);

		if (chunk->external) {
			is_external = 1;
			break;
		} else if (!chunk->fullfile) {
			has_chunk = 1;
		}

		chunk = chunk->next;
	}

	if (is_external) {
		fbr_rlog(FBR_LOG_IOCMD_MERGE, "External chunk detected");
		return EIO;
	} else if (!has_chunk || !file_size) {
		fbr_rlog(FBR_LOG_IOCMD_MERGE, "No chunks detected");
		return EIO;
	}

	int ret = EOPNOTSUPP;

	if (fs->store->merge_file_f) {
		ret = fs->store->merge_file_f(fs, file);
	}

	if (ret) {
		return ret;
	}

	// TODO import

	return 1;
}
