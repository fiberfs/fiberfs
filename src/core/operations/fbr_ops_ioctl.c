/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/iocmd/fbr_iocmd.h"

static struct {
	unsigned long			command;
	fbr_iocmd_f			*callback;
} _FBR_IOCMD_ROUTES[2] = {
	{
		FBR_IOCMD_PING_REQ,
		fbr_iocmd_pong
	},{
		FBR_IOCMD_IMPORT_REQ,
		fbr_iocmd_import
	}
};

void
fbr_ops_ioctl(struct fbr_request *request, fuse_ino_t ino, unsigned int cmd, void *arg,
    struct fuse_file_info *fi, unsigned flags, const void *in_buf, size_t in_bufsz,
    size_t out_bufsz)
{
	struct fbr_fs *fs = fbr_request_fs(request);
	assert_zero(fbr_is_flag(flags, FUSE_IOCTL_UNRESTRICTED));
	(void)arg;
	(void)fi;
	(void)in_buf;

	fbr_rlog(FBR_LOG_OP, "IOCTL req: %lu ino: %lu cmd: %u in_bufsz: %zu out_bufsz: %zu",
		request->id, ino, cmd, in_bufsz, out_bufsz);

	struct fbr_file *file = fbr_inode_take_alias(fs, ino);
	if (!file) {
		fbr_fuse_reply_err(request, ENOENT);
		return;
	}

	char buffer[4096];
	char *out_buf = NULL;
	if (out_bufsz) {
		if (out_bufsz > sizeof(buffer)) {
			fbr_fuse_reply_err(request, ENOMEM);
			fbr_inode_release(fs, &file);
			return;
		}

		out_buf = buffer;

		memset(out_buf, 0, out_bufsz);
	}

	int error = EIO;

	size_t i;
	for (i = 0; i < fbr_array_len(_FBR_IOCMD_ROUTES); i++) {
		if (cmd == _FBR_IOCMD_ROUTES[i].command) {
			error = _FBR_IOCMD_ROUTES[i].callback(fs, file, cmd, in_buf, out_buf);
			break;
		}
	}

	if (i >= fbr_array_len(_FBR_IOCMD_ROUTES)) {
		fbr_rlog(FBR_LOG_OP_IOCTL, "ERROR cmd not found (%d %d %d %d)",
			_IOC_DIR(cmd), _IOC_TYPE(cmd), _IOC_NR(cmd), _IOC_SIZE(cmd));
	}

	fbr_inode_release(fs, &file);

	if (error) {
		fbr_fuse_reply_err(request, error);
		return;
	}

	fbr_fuse_reply_ioctl(request, 0, out_buf, out_bufsz);
}
