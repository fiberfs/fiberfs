/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_forget(struct fbr_request *request, fuse_ino_t ino, uint64_t nlookup)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "FORGET req: %lu ino: %lu nlookup: %lu", request->id, ino, nlookup);

	fbr_inode_forget(fs, ino, nlookup);
	fbr_fuse_reply_none(request);
}

void
fbr_ops_forget_multi(struct fbr_request *request, size_t count, struct fuse_forget_data *forgets)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "FORGET_M req: %lu count: %zu", request->id, count);

	for (size_t i = 0; i < count; i++) {
		fbr_rlog(FBR_LOG_OP_FORGET, "multi ino: %lu nlookup: %lu", forgets[i].ino,
			forgets[i].nlookup);

		fbr_inode_forget(fs, forgets[i].ino, forgets[i].nlookup);
	}

	fbr_fuse_reply_none(request);
}
