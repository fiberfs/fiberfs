/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdio.h>

#include "fiberfs.h"
#include "fbr_main.h"
#include "core/fs/fbr_fs.h"
#include "core/fuse/fbr_fuse.h"
#include "core/request/fbr_request.h"
#include "cstore/fbr_cstore_api.h"
#include "log/fbr_log.h"
#include "utils/fbr_sys.h"

static void
_mount_fuse_init(struct fbr_fuse_context *fuse_ctx, struct fuse_conn_info *conn)
{
	fbr_fuse_mounted(fuse_ctx);
	fbr_fs_ok(fuse_ctx->fs);
	assert(conn);
	assert_zero(fbr_is_test());

	fbr_fuse_setup(fuse_ctx, conn);

	struct fbr_cstore_hashpath cache_hashroot;
	const char *cache_root = fbr_conf_get("CACHE_ROOT", FBR_CSTORE_DEFAULT_ROOT);
	fbr_cstore_make_root(&cache_hashroot, cache_root, fuse_ctx->path);

	fbr_rlog(FBR_LOG_MOUNT, "cache root: %s", cache_hashroot.value);

	// Init cstore
	struct fbr_cstore *cstore = fbr_cstore_alloc(cache_hashroot.value);
	fbr_cstore_ok(cstore);

	unsigned int cache_size = fbr_conf_get_ulong("CACHE_SIZE_MB", FBR_CSTORE_DEFAULT_SIZE_MB);
	cache_size *= 1024 * 1024;
	fbr_cstore_max_size(cstore, cache_size, 1);

	assert_zero(fuse_ctx->fs->cstore);
	fuse_ctx->fs->cstore = cstore;
	fbr_fs_set_store(fuse_ctx->fs, FBR_CSTORE_DEFAULT_CALLBACKS);

	int ret = fbr_cstore_autoinit(cstore);
	assert_zero(ret);

	struct fbr_request *request = fbr_request_alloc(NULL, __func__);
	fbr_request_ok(request);
	assert_zero(request->not_fuse);

	// Init fs
	fbr_directory_root_inode_init(fuse_ctx->fs);

	// TODO we need the status from fbr_index_read()

	// Try and read the root index
	struct fbr_directory *root = fbr_directory_from_inode(fuse_ctx->fs, FBR_INODE_ROOT);
	if (root) {
		fbr_directory_ok(root);
		assert(root->state == FBR_DIRSTATE_OK);

		fbr_rlog(FBR_LOG_MOUNT, "root loaded OK");

		fbr_dindex_release(fuse_ctx->fs, &root);
		fbr_request_free(request);

		return;
	}

	// Create a new root
	root = fbr_directory_make(fuse_ctx->fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT);
	if (!root) {
		fbr_rlog(FBR_LOG_MOUNT, "root creation ERROR");

		fuse_ctx->error = 1;

		fbr_request_free(request);

		return;
	}

	fbr_rlog(FBR_LOG_MOUNT, "root creation SUCCESS");

	fbr_dindex_release(fuse_ctx->fs, &root);
	fbr_request_free(request);
}

int
fiberfs_mount(struct fbr_main_params *main_params)
{
	assert(main_params);
	assert_zero(main_params->commands.count);

	if (main_params->arg_count != 2) {
		fbr_main_usage();
		return 1;
	}

	printf("FiberFS %s\n", FIBERFS_VERSION);

	const char *fiberfs_conf = main_params->args[0];
	const char *mount_path = main_params->args[1];

	if (!fbr_sys_isfile(fiberfs_conf)) {
		fprintf(stderr, "ERROR: config not found '%s'\n", fiberfs_conf);
		return 1;
	} else if (!fbr_sys_isdir(mount_path)) {
		fprintf(stderr, "ERROR: mount not found '%s'\n", mount_path);
		return 1;
	}

	fbr_conf_parse(fiberfs_conf);
	assert_zero(_CONFIG->stats.errors);

	int ret = fbr_cstore_autoinit(NULL);
	if (ret) {
		fprintf(stderr, "ERROR: no S3 config in '%s'\n", fiberfs_conf);
		return 1;
	}

	// Init fuse
	struct fbr_fuse_context _fuse_ctx;
	struct fbr_fuse_context *fuse_ctx = &_fuse_ctx;
	fbr_fuse_init(fuse_ctx);
	fbr_fuse_set_callbacks(fuse_ctx, _mount_fuse_init, FBR_FUSE_DEFAULT_CALLBACKS);

	ret = fbr_fuse_mount(fuse_ctx, mount_path);
	if (ret) {
		fprintf(stderr, "ERROR: cannot mount '%s'\n", mount_path);

		fbr_fuse_unmount(fuse_ctx);

		return 2;
	}

	while (!FBR_MAIN_STOP) {
		fbr_fuse_mounted(fuse_ctx);
		assert_zero(fuse_ctx->detached);
		fbr_sleep_ms(FBR_MOUNT_LOOP_MS);
	}

	fbr_fuse_unmount(fuse_ctx);
	assert(fuse_ctx->state == FBR_FUSE_NONE);

	fbr_fuse_free(fuse_ctx);

	printf("Exiting\n");

	return 0;
}
