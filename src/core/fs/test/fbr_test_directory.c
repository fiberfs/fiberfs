/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdlib.h>

#include "core/fs/fbr_fs.h"
#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"

#define _TEST_DIR_THREADS		3
#define _TEST_DIR_MAX_TIME		2.0

int _TEST_ROOT;
fbr_inode_t _TEST_INODE;
unsigned long _TEST_DIR_THREAD;
unsigned long _TEST_DIR_VERSION;

static void *
_alloc_parallel(void *arg)
{
	struct fbr_fs *fs = (struct fbr_fs*)arg;
	fbr_fs_ok(fs);

	unsigned long id = fbr_safe_add(&_TEST_DIR_THREAD, 1);

	fbr_test_logs("root thread_%lu: started", id);

	double time_start = fbr_get_time();

	while (fbr_get_time() - time_start < _TEST_DIR_MAX_TIME) {
		struct fbr_directory *directory = NULL;

		if (_TEST_ROOT) {
			directory = fbr_directory_root_alloc(fs);
		} else {
			assert(_TEST_INODE > FBR_INODE_ROOT);

			struct fbr_path_name filename;
			fbr_path_name_init(&filename, "random");

			directory = fbr_directory_alloc(fs, &filename, _TEST_INODE);
		}

		fbr_directory_ok(directory);

		if (directory->state == FBR_DIRSTATE_OK) {
			fbr_dindex_release(fs, &directory);
			continue;
		}

		unsigned long version = fbr_safe_add(&_TEST_DIR_VERSION, 1);
		int do_error = (random() % 3 == 0);

		assert(directory->state == FBR_DIRSTATE_LOADING);

		directory->version = version;

		fbr_test_logs("thread_%lu: version %lu error: %d stale: %s stale_version: %lu",
			id, version, do_error,
			directory->stale ? "true" : "false",
			directory->stale ? directory->stale->version: 0);

		char namebuf[128];
		ssize_t ret = snprintf(namebuf, sizeof(namebuf), "file_%lu", version);
		assert((size_t)ret < sizeof(namebuf));

		struct fbr_path_name filename;

		fbr_path_name_init(&filename, namebuf);
		(void)fbr_file_alloc(fs, directory, &filename, S_IFREG | 0444);

		fbr_sleep_ms(random() % 50);

		if (do_error) {
			fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
		} else {
			fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
		}

		fbr_sleep_ms(1);

		fbr_dindex_release(fs, &directory);
	}

	return NULL;
}

void
_directory_parallel(void)
{
	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->log = fbr_fs_test_logger;

	fbr_test_random_seed();

	_TEST_INODE = 0;
	_TEST_DIR_THREAD = 0;
	_TEST_DIR_VERSION = 0;

	unsigned long version = fbr_safe_add(&_TEST_DIR_VERSION, 1);
	assert(version == 1);

	struct fbr_directory *directory = NULL;
	struct fbr_file *file = NULL;

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_test_ASSERT(fs->root, "fs->root is missing");

	if (_TEST_ROOT) {
		directory = root;
	} else {
		struct fbr_path_name filename;
		fbr_path_name_init(&filename, "random");

		struct fbr_file *file = fbr_file_alloc(fs, root, &filename, S_IFDIR);
		assert(file->parent_inode == root->inode);

		fbr_inode_add(fs, file);

		fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

		fbr_dindex_release(fs, &root);

		_TEST_INODE = file->inode;

		directory = fbr_directory_alloc(fs, &filename, _TEST_INODE);
	}

	fbr_directory_ok(directory);
	directory->version = version;

	fbr_test_logs("INODE=%lu", directory->inode);

	pthread_t threads[_TEST_DIR_THREADS];

	for (size_t i = 0; i < _TEST_DIR_THREADS; i++) {
		assert_zero(pthread_create(&threads[i], NULL, _alloc_parallel, fs));
	}

	if (random() % 4) {
		fbr_test_logs("main: version %lu error: 0", version);
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	} else {
		fbr_test_logs("main: version %lu error: 1", version);
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
	}

	fbr_dindex_release(fs, &directory);

	for (size_t i = 0; i < _TEST_DIR_THREADS; i++) {
		assert_zero(pthread_join(threads[i], NULL));
	}

	if (file) {
		fbr_inode_release(fs, &file);
	}

	fbr_test_logs("threads exited");

	fbr_fs_release_all(fs, 1);

	fbr_fs_test_stats(fs);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_fs_free(fs);
}

void
fbr_cmd_fs_test_root_parallel(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_TEST_ROOT = 1;

	_directory_parallel();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "root parallel test done");
}

void
fbr_cmd_fs_test_directory_parallel(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_TEST_ROOT = 0;

	_directory_parallel();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "directory parallel test done");
}
