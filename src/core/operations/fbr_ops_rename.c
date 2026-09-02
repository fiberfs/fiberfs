/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"

void
fbr_ops_rename(struct fbr_request *request, fuse_ino_t parent, const char *name,
    fuse_ino_t newparent, const char *newname, unsigned int flags)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "RENAME req: %lu parent: %lu name: '%s' newparent: %lu newname: '%s'"
		" flags: %d", request->id, parent, name, newparent, newname, flags);

	(void)fs;

	fbr_fuse_reply_err(request, ENOSYS);
}
