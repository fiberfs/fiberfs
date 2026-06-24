/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/operations/fbr_operations.h"
#include "core/request/fbr_request.h"
#include "utils/fbr_sys.h"

static void _mount_fuse_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn);

static const struct fbr_fuse_callbacks _FIBERFS_FUSE_CALLBACKS = {
	.init = _mount_fuse_init,

	.getattr = fbr_ops_getattr,
	.setattr = fbr_ops_setattr,
	.lookup = fbr_ops_lookup,

	.mkdir = fbr_ops_mkdir,
	.unlink = fbr_ops_unlink,
	.rmdir = fbr_ops_rmdir,

	.opendir = fbr_ops_opendir,
	.readdir = fbr_ops_readdir,
	.releasedir = fbr_ops_releasedir,

	.open = fbr_ops_open,
	.create = fbr_ops_create,
	.read = fbr_ops_read,
	.write = fbr_ops_write,
	.flush = fbr_ops_flush,
	.release = fbr_ops_release,
	.fsync = fbr_ops_fsync,

	.forget = fbr_ops_forget,
	.forget_multi = fbr_ops_forget_multi
};

static void
_mount_fuse_init(struct fbr_fuse_context *ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(ctx);
	assert_zero(ctx->detached);
	fbr_fs_ok(ctx->fs);
	assert(conn);

	printf("Fuse init\n");
}

static void
_usage(void)
{
	printf("Usage: fiberfs CONFIG MOUNT_PATH\n");
}

int
main(int argc, char **argv)
{
	printf("FiberFS %s\n", FIBERFS_VERSION);

	if (argc != 3) {
		_usage();
		return 1;
	}

	const char *fiberfs_conf = argv[1];
	const char *mount_path = argv[2];

	if (!fbr_sys_isfile(fiberfs_conf)) {
		_usage();
		fprintf(stderr, "ERROR: config not found '%s'\n", fiberfs_conf);
		return 1;
	} else if (!fbr_sys_isdir(mount_path)) {
		_usage();
		fprintf(stderr, "ERROR: mount not found '%s'\n", mount_path);
		return 1;
	}

	struct fbr_fuse_context fuse_ctx;
	fbr_fuse_init(&fuse_ctx);
	fuse_ctx.fuse_callbacks = &_FIBERFS_FUSE_CALLBACKS;

	int ret = fbr_fuse_mount(&fuse_ctx, mount_path);
	if (ret) {
		return 2;
	}

	printf("Unmounting\n");

	fbr_fuse_unmount(&fuse_ctx);
	assert(fuse_ctx.state == FBR_FUSE_NONE);

	fbr_fuse_free(&fuse_ctx);

	printf("Done\n");

	return 0;
}
