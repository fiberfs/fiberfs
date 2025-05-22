/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/store/test/fbr_dstore.h"

static const struct fbr_store_callbacks _WRITE_CALLBACKS = {
	.chunk_read_f = fbr_dstore_chunk_read,
	.chunk_delete_f = fbr_dstore_chunk_delete,
	.wbuffer_write_f = fbr_dstore_wbuffer_write,
	.wbuffers_flush_f = fbr_test_fs_rw_wbuffers_flush,
	.index_write_f = fbr_dstore_index_root_write,
	.index_read_f = fbr_dstore_index_read,
	.root_read_f = fbr_dstore_root_read
};

static void
_write_test(void)
{
	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);

	fbr_fs_set_store(fs, &_WRITE_CALLBACKS);

	fbr_fs_free(fs);
}

void
fbr_cmd_store_write(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_write_test();

	fbr_test_logs("store_write done");
}
