/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_write(struct fbr_request *request, fuse_ino_t ino, const char *buf, size_t size,
    off_t off, struct fuse_file_info *fi)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fs->log("WRITE req: %lu ino: %lu off: %ld size: %zu", request->id, ino, off, size);
	assert(off >= 0);
	assert(size);

	struct fbr_fio *fio = fbr_fh_fio(fi->fh);
	fbr_fio_take(fio);
	fbr_file_ok(fio->file);
	assert(fio->file->inode == ino);

	fbr_wbuffer_write(fs, fio, off, buf, size);

	fbr_fs_stat_add_count(&fs->stats.write_bytes, size);

	int ret = 0;
	if (fio->append) {
		ret = fbr_wbuffer_flush_fio(fs, fio);
	}

	if (!ret) {
		fbr_fuse_reply_write(request, size);
	} else {
		fbr_fuse_reply_err(request, ret);
	}

	fbr_fio_release(fs, fio);
}
