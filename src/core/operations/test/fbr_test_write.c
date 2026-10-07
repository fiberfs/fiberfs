/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "cstore/test/fbr_test_cstore_cmds.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"

void
fbr_cmd_remote_append(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR(cmd->param_count < 2, "Need 2 params");
	assert(fbr_test_cstore_count(ctx) == 1);

	const char *filename = cmd->params[0].value;

	struct fbr_fs *fs_remote = fbr_test_fs_alloc();
	fbr_fs_ok(fs_remote);
	fbr_test_cstore_bind(fs_remote, 0);
	fbr_fs_set_store(fs_remote, FBR_CSTORE_DEFAULT_CALLBACKS);

	struct fbr_request *request = fbr_test_request_mock();
	fbr_request_valid(request);
	request->fs = fs_remote;
	request->id = 77777;
	request->rlog->request_id = request->id;

	struct fbr_directory *root = fbr_directory_load(fs_remote, FBR_DIRNAME_ROOT,
		FBR_INODE_ROOT, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	struct fbr_file *file = fbr_directory_find_file(root, filename, cmd->params[0].len);
	fbr_file_ok(file);

	for (size_t i = 1; i < cmd->param_count; i++) {
		request->id++;
		request->rlog->request_id = request->id;

		struct fbr_fio *fio = fbr_fio_alloc(fs_remote, file, 0);
		fio->append = 1;

		fbr_wbuffer_write(fs_remote, fio, 0, cmd->params[i].value, cmd->params[i].len);
		int ret = fbr_wbuffer_flush_fio(fs_remote, fio);
		assert_zero(ret);

		fbr_fio_release(fs_remote, fio);
	}

	fbr_dindex_release(fs_remote, &root);
	fbr_fs_free(fs_remote);
	fbr_request_free(request);

	fbr_test_logs("remote_append: %s", filename);
}
