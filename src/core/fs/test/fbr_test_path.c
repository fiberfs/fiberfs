/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_path.h"
#include "test/fbr_test.h"

void
fbr_cmd_fs_test_path_assert(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	struct fbr_path *path;

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "enum FBR_PATH_LAYOUT end=%d",
		__FBR_PATH_LAYOUT_END);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_LAYOUT_LEN=%d",
		FBR_PATH_LAYOUT_LEN);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_path_ptr)=%zu",
		sizeof(struct fbr_path_ptr));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_path_embed)=%zu",
		sizeof(struct fbr_path_embed));
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(struct fbr_path)=%zu",
		sizeof(struct fbr_path));

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_EMBED_LEN_SIZE=%d",
		FBR_PATH_EMBED_LEN_SIZE);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_PTR_LEN_SIZE=%zu",
		FBR_PATH_PTR_LEN_SIZE);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "FBR_PATH_EMBED_LEN=%zu", FBR_PATH_EMBED_LEN);
	fbr_test_log(ctx, FBR_LOG_VERBOSE, "sizeof(path->embed.data)=%zu",
		sizeof(path->embed.data));

	fbr_test_ASSERT(__FBR_PATH_LAYOUT_END <= (1<<FBR_PATH_LAYOUT_LEN),
		"FBR_PATH_LAYOUT doesnt fit in %d bits", FBR_PATH_LAYOUT_LEN);
	fbr_test_ASSERT(sizeof(struct fbr_path_ptr) == sizeof(struct fbr_path_embed),
		"struct fbr_path_ptr != struct fbr_path_embed");
	fbr_test_ASSERT(sizeof(struct fbr_path) == sizeof(struct fbr_path_embed),
		"struct fbr_path != struct fbr_path_embed");
}
