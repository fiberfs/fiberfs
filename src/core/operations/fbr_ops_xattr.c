/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "cstore/fbr_cstore_path.h"

#define FBR_XATTR_NAMESPACE	"user" FBR_FIBERFS_NAME

void
fbr_ops_xattr_list(struct fbr_request *request, fuse_ino_t ino, size_t size)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "XATTR_LIST req: %lu ino: %lu size: %lu", request->id, ino, size);

	struct fbr_file *file = fbr_inode_take_alias(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_inode_release(fs, &file);

	size_t xattr_size = 0;
	xattr_size += sizeof(FBR_FIBERFS_NAME);
	xattr_size += sizeof(FBR_XATTR_NAMESPACE);

	if (!size) {
		fbr_fuse_reply_xattr(request, xattr_size);
		return;
	} else if (size < xattr_size) {
		fbr_fuse_reply_err(request, ERANGE);
	}

	char buffer[256];
	size_t buffer_len = 0;
	assert(xattr_size <= sizeof(buffer));

	buffer_len += fbr_snaprintf(buffer, sizeof(buffer), buffer_len, "%s", FBR_FIBERFS_NAME);
	buffer_len++;

	buffer_len += fbr_snaprintf(buffer, sizeof(buffer), buffer_len, "%s", FBR_XATTR_NAMESPACE);
	buffer_len++;

	assert(buffer_len == xattr_size);

	fbr_fuse_reply_buf(request, buffer, buffer_len);
}

void
fbr_ops_xattr_get(struct fbr_request *request, fuse_ino_t ino, const char *name, size_t size)
{
	struct fbr_fs *fs = fbr_request_fs(request);

	fbr_rlog(FBR_LOG_OP, "XATTR_GET req: %lu ino: %lu name: %s size: %lu", request->id, ino,
		name, size);

	struct fbr_file *file = fbr_inode_take_alias(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	fbr_inode_release(fs, &file);

	const char *xattr_value = NULL;
	size_t xattr_size = 0;

	if (!strcmp(name, FBR_FIBERFS_NAME)) {
		xattr_value = FIBERFS_VERSION;
		xattr_size = sizeof(FIBERFS_VERSION);
	} else if (!strcmp(name, FBR_XATTR_NAMESPACE)) {
		xattr_value = FIBERFS_VERSION;
		xattr_size = sizeof(FIBERFS_VERSION);
	}

	if (!xattr_size) {
		fbr_fuse_reply_err(request, ENODATA);
		return;
	} else if (!size) {
		fbr_fuse_reply_xattr(request, xattr_size);
		return;
	} else if (size < xattr_size) {
		fbr_fuse_reply_err(request, ERANGE);
	}

	char buffer[256];
	assert(xattr_size <= sizeof(buffer));
	assert(xattr_value);

	size_t buffer_len = fbr_strbcpy(buffer, xattr_value);
	buffer_len++;
	assert(buffer_len == xattr_size);

	fbr_fuse_reply_buf(request, buffer, buffer_len);
}
