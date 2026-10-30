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

	// TODO move this into a flush_cmd (post operation) so we are atomic on upload
	// We also need etags on imported and merged fullfiles

	const struct fbr_iocmd_merge *io_merge = input;

	if (!fbr_object_is_valid(io_merge, FBR_IOCMD_MERGE_MAGIC)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR magic");
		return EIO;
	} else if (!fs->cstore || !fbr_cstore_backend_enabled(fs->cstore)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR cstore");
		return EIO;
	}

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	struct fbr_path_name dirpath;
	fbr_path_get_dir(&file->path, &dirpath);

	struct fbr_directory *directory = fbr_directory_get(fs, &dirpath, file->parent_inode, 0, 1);
	if (!directory) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR directory");
		return ENOENT;
	}

	file = fbr_directory_find_file(directory, filename.name, filename.length);

	if (!file) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR no file");
		fbr_dindex_release(fs, &directory);
		return EINVAL;
	} else if (!fbr_file_is_file(file)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR not file");
		fbr_dindex_release(fs, &directory);
		return EINVAL;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_rlog(FBR_LOG_IOCMD_MERGE, "file: '%s' inode: %lu gen: %lu", filename.name, file->inode,
		file->generation);

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
		fbr_dindex_release(fs, &directory);
		return EIO;
	} else if (!has_chunk || !file_size) {
		fbr_rlog(FBR_LOG_IOCMD_MERGE, "No chunks detected");
		fbr_dindex_release(fs, &directory);
		return EIO;
	}

	int ret = EOPNOTSUPP;

	if (fs->store->merge_file_f) {
		ret = fs->store->merge_file_f(fs, file);
	}

	if (ret) {
		fbr_dindex_release(fs, &directory);
		return ret;
	}

	struct fbr_iocmd_import io_import;
	fbr_iocmd_import_init(&io_import);
	io_import.filename.path.length = fbr_strbcpy(io_import.filename.data, filename.name);
	io_import.overwrite = 1;
	io_import.merged = 1;

	ret = fbr_iocmd_import(fs, directory->file, FBR_IOCMD_IMPORT_REQ, &io_import, NULL);

	fbr_dindex_release(fs, &directory);

	return ret;
}
