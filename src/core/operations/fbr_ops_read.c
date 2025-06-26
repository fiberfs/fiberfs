/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_read(struct fbr_request *request, fuse_ino_t ino, size_t size, off_t off,
    struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fs->log("READ req: %lu ino: %lu off: %ld size: %zu flags: %d", request->id, ino, off,
		size, fi->flags);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_take(fio);
	fbr_file_ok(fio->file);

	struct fbr_chunk_vector *vector = fbr_fio_vector_gen(fs, fio, off, size);
	if (!vector) {
		if (fio->error) {
			fbr_fuse_reply_err(request, EIO);
		} else {
			fbr_fuse_reply_buf(request, NULL, 0);
		}

		fbr_fio_release(fs, fio);

		return;
	}

	fbr_chunk_list_ok(vector->chunks);
	assert(vector->bufvec);

	fs->log("READ chunks: %u bufvecs: %zu", vector->chunks->length, vector->bufvec->count);
	fbr_fs_stat_add_count(&fs->stats.read_bytes, vector->size);

	fbr_fuse_reply_data(request, vector->bufvec, FUSE_BUF_SPLICE_MOVE);

	fbr_fio_vector_free(fs, fio, vector);

	fbr_fio_release(fs, fio);
}
