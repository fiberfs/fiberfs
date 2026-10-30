/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_iocmd.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/request/fbr_request.h"
#include "core/request/fbr_rlog.h"
#include "cstore/fbr_cstore_api.h"
#include "cstore/s3/fbr_cstore_s3.h"

int
fbr_iocmd_import(struct fbr_fs *fs, struct fbr_file *directory_file, unsigned long command,
   const void *input, void *output)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_file_ok(directory_file);
	assert(command == FBR_IOCMD_IMPORT_REQ);
	assert(input);
	assert_zero(output);

	const struct fbr_iocmd_import *io_import = input;

	struct fbr_request *request = fbr_request_get();
	fbr_request_ok(request);

	struct fuse_ctx fusectx;
	const struct fuse_ctx *fctx = fbr_fuse_req_ctx(request, &fusectx);
	assert(fctx);

	if (!fbr_object_is_valid(io_import, FBR_IOCMD_IMPORT_MAGIC)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR magic");
		return EIO;
	} else if (!io_import->filename.path.length) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR length");
		return EINVAL;
	} else if (!fs->cstore) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR cstore");
		return EIO;
	} else if (!fbr_file_is_dir(directory_file)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR directory_file");
		return ENOTDIR;
	} else if (!fbr_fuse_check_access(fctx, directory_file, W_OK | X_OK)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR access");
		return EPERM;
	}

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, io_import->filename.data);
	assert_dev(filename.length == io_import->filename.path.length);
	assert_zero_dev(io_import->filename.path.name);

	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "request: '%s' overwrite: %d", filename.name,
		io_import->overwrite);

	struct fbr_directory *directory = fbr_directory_from_inode(fs, directory_file->inode);
	if (!directory) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR no directory");
		return ENOTDIR;
	}

	struct fbr_path_name dirpath;
	fbr_path_shared_name(directory->path, &dirpath);

	int error = fbr_check_name(&dirpath, &filename);
	if (error) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR name");
		fbr_dindex_release(fs, &directory);
		return error;
	}

	struct fbr_file *existing_file = fbr_directory_find_file(directory, filename.name,
		filename.length);

	if (existing_file && !io_import->overwrite) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR existing_file");
		fbr_dindex_release(fs, &directory);
		return EEXIST;
	} else if (existing_file && fbr_file_is_dir(existing_file)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR existing_file is directory");
		fbr_dindex_release(fs, &directory);
		return EISDIR;
	}

	struct fbr_file *import_file = fbr_file_alloc_new(fs, directory, &filename);
	assert(import_file->parent_inode == directory->inode);
	assert(import_file->state == FBR_FILE_INIT);

	fbr_inode_add(fs, import_file);
	fbr_dindex_release(fs, &directory);

	const char *import_filename = fbr_path_get_file(&import_file->path, NULL);
	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "new file: inode: %lu filename: '%s'", import_file->inode,
		import_filename);
	assert_zero_dev(strcmp(import_filename, filename.name));

	import_file->uid = fctx->uid;
	import_file->gid = fctx->gid;
	import_file->mode = (fbr_ulong2octal(666) & ~(fctx->umask)) | S_IFREG;
	import_file->local_only = 1;
	import_file->silent_import = 1;

	fbr_id_t id = fbr_id_gen();
	size_t size = 0;

	struct fbr_cstore_url url;
	fbr_cstore_ok(fs->cstore);
	fbr_cstore_s3_fullfile_url(fs->cstore, import_file, id, &url);

	error = EOPNOTSUPP;

	if (fs->store->external_file_size) {
		error = fs->store->external_file_size(fs, &url, &size);
	}

	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "S3 ret: %d size: %zu", error, size);

	if (error || !size) {
		fbr_inode_release(fs, &import_file);

		if (error == 404) {
			return ENOENT;
		}

		return EIO;
	}

	assert_zero(import_file->size);
	assert_zero(import_file->body.chunks);
	assert_zero_dev(import_file->body.chunk_last);

	size_t debug_chunk_size = fs->config.debug_import_chunk_size;
	size_t chunk_count = 0;
	size_t offset = 0;

	if (debug_chunk_size) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "DEBUG import_chunk_size: %lu", debug_chunk_size);
	}

	while (import_file->size < size) {
		size_t length = fbr_fs_chunk_size(offset);
		if (debug_chunk_size && debug_chunk_size < length) {
			length = debug_chunk_size;
			debug_chunk_size *= 2;
		}

		if (offset + length > size) {
			assert_dev(size > offset);
			length = size - offset;
		}

		struct fbr_chunk *chunk = fbr_body_chunk_add(fs, import_file, id, offset, length);
		assert(chunk);
		assert_dev(chunk->length == length);
		assert_dev(chunk->id = id);

		chunk->fullfile = 1;
		chunk->external = 1;

		assert(import_file->size > offset);

		offset = import_file->size;
		chunk_count++;
	}

	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "chunks: %zu file->size: %zu", chunk_count,
		import_file->size);

	assert_dev(import_file->size == size);

	import_file->silent_import = 0;

	enum fbr_flush_flags flags = FBR_FLUSH_IMPORT | FBR_FLUSH_IMPORT_UNIQUE;
	if (io_import->overwrite) {
		flags = FBR_FLUSH_IMPORT;
	}

	struct fbr_flush_data flush_data;
	fbr_flush_data_init(&flush_data, import_file, NULL, NULL, NULL, flags, NULL);

	int ret = fbr_fs_flush(fs, &flush_data);
	if (ret) {
		fbr_inode_release(fs, &import_file);
		return ret;
	}

	fbr_file_ok(import_file);
	assert(import_file->state >= FBR_FILE_OK);
	assert_zero(import_file->local_only);

	fbr_inode_release(fs, &import_file);

	return 0;
}
