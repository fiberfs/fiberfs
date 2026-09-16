/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <fcntl.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_fs_inline.h"
#include "core/operations/fbr_operations.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "core/fs/test/fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "core/request/test/fbr_test_request_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

static struct fbr_request *
_rename_request(struct fbr_fs *fs)
{
	fbr_fs_ok(fs);

	struct fbr_request *request = fbr_request_get();
	if (request) {
		fbr_request_free(request);
	}

	request = fbr_test_request_mock();
	fbr_fuse_detached(request->fuse_ctx);
	request->fs = fs;
	fbr_request_valid(request);
	assert_zero(request->error);

	return request;
}

static void
_rename_test(struct fbr_test_context *ctx, int append)
{
	assert_dev(ctx);

	fbr_test_fuse_mock(ctx);
	fbr_test_request_pool_register(ctx);

	struct fbr_fs *fs = fbr_test_fs_alloc();
	fbr_fs_ok(fs);
	fbr_fs_set_store(fs, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_bind_new(fs);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Create root");

	fbr_test_fs_root_alloc(fs);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Create file.1");

	struct fbr_path_name filename1;
	fbr_path_name_init(&filename1, "file.1");
	struct fbr_path_name filename2;
	fbr_path_name_init(&filename2, "file.2");

	struct fbr_request *request = _rename_request(fs);

	struct fbr_directory *root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	struct fuse_file_info fi;
	fbr_zero(&fi);
	fi.flags = O_CREAT | O_WRONLY;

	fbr_ops_create(request, FBR_INODE_ROOT, filename1.name, S_IFREG, &fi);
	assert_zero(request->error);

	struct fbr_fio *fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);

	request = _rename_request(fs);

	fbr_ops_write(request, fio->file->inode, "pre_rename", 10, 0, &fi);
	assert_zero(request->error);

	request = _rename_request(fs);

	fbr_ops_release(request, fio->file->inode, &fi);
	assert_zero(request->error);

	fbr_dindex_release(fs, &root);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Append to file.1 (1)");

	root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);

	struct fbr_file *file = fbr_directory_find_file(root, filename1.name, filename1.length);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);

	fbr_inode_add(fs, file);
	fbr_dindex_release(fs, &root);

	request = _rename_request(fs);

	fbr_zero(&fi);
	if (append) {
		fi.flags = O_WRONLY | O_APPEND;
	} else {
		fi.flags = O_WRONLY;
	}

	fbr_ops_open(request, file->inode, &fi);
	assert_zero(request->error);

	fio = fbr_fh_fio(fi.fh);
	fbr_file_ok(fio->file);
	assert(fio->file == file);

	request = _rename_request(fs);

	fbr_ops_write(request, fio->file->inode, " append1", 8, 0, &fi);
	assert_zero(request->error);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Rename file.1 to file.2");

	request = _rename_request(fs);

	fbr_ops_rename(request, FBR_INODE_ROOT, filename1.name, FBR_INODE_ROOT, filename2.name, 0);
	assert_zero(request->error);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Append to file.1 (2)");

	request = _rename_request(fs);

	fbr_ops_write(request, fio->file->inode, " append2", 8, 0, &fi);
	assert_zero(request->error);

	request = _rename_request(fs);

	fbr_ops_release(request, file->inode, &fi);
	assert_zero(request->error);
	fbr_inode_release(fs, &file);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Validate file.2");

	root = fbr_directory_get(fs, FBR_DIRNAME_ROOT, FBR_INODE_ROOT, 0, 0);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_OK);
	assert(root->file_count == 1);

	file = fbr_directory_find_file(root, filename2.name, filename2.length);
	fbr_file_ok(file);
	assert(file->state == FBR_FILE_OK);
	if (append) {
		fbr_ASSERT(file->size == 26, "found size: %lu", file->size);
	} else {
		fbr_ASSERT(file->size == 10, "found size: %lu", file->size);
	}

	char buf[128];
	size_t bytes = fbr_test_fs_read(fs, file, 0, buf, sizeof(buf));
	assert(bytes < sizeof(buf));
	buf[bytes] = '\0';
	if (append) {
		fbr_ASSERT(!strcmp(buf, "pre_rename append1 append2"), "found: '%s'", buf);
	} else {
		fbr_ASSERT(!strcmp(buf, " append2me"), "found: '%s'", buf);
	}

	fbr_dindex_release(fs, &root);

	fbr_test_sleep_ms(20);
	fbr_test_logs("*** Cleanup fs");

	fbr_request_free(request);
	fbr_fs_release_all(fs, 1);

	fbr_test_cstore_debug(fs->cstore);
	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);

	if (append) {
		assert(fs->cstore->stats.wr_chunks == 3);
	} else {
		assert(fs->cstore->stats.wr_chunks == 2);
	}

	assert_zero(fs->stats.directories);
	assert_zero(fs->stats.directories_dindex);
	assert_zero(fs->stats.directory_refs);
	assert_zero(fs->stats.files);
	assert_zero(fs->stats.files_inodes);
	assert_zero(fs->stats.file_refs);

	fbr_fs_free(fs);

	if (append) {
		fbr_test_logs("rename_append_test done");
	} else {
		fbr_test_logs("rename_write_test done");
	}
}

void
fbr_cmd_rename_append_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_rename_test(ctx, 1);
}

void
fbr_cmd_rename_write_test(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_rename_test(ctx, 0);
}
