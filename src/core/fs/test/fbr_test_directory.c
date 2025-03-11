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

unsigned long _TEST_DIR_THREAD;
unsigned long _TEST_DIR_COUNTER;

static void *
_root_parallel(void *arg)
{
	struct fbr_fs *fs = (struct fbr_fs*)arg;
	fbr_fs_ok(fs);

	unsigned long id = fbr_safe_add(&_TEST_DIR_THREAD, 1);

	fbr_test_logs("root thread_%lu: started", id);

	double time_start = fbr_get_time();

	while (fbr_get_time() - time_start < _TEST_DIR_MAX_TIME) {
		struct fbr_directory *root = fbr_directory_root_alloc(fs);

		if (root->state == FBR_DIRSTATE_OK) {
			fbr_dindex_release(fs, &root);
			continue;
		}

		unsigned long version = fbr_safe_add(&_TEST_DIR_COUNTER, 1);
		int do_error = (random() % 3 == 0);

		assert(root->state == FBR_DIRSTATE_LOADING);

		root->version = version;

		fbr_test_logs("thread_%lu: version %lu error: %d stale: %s stale_version: %lu",
			id, version, do_error,
			root->stale ? "true" : "false",
			root->stale ? root->stale->version: 0);

		char namebuf[128];
		ssize_t ret = snprintf(namebuf, sizeof(namebuf), "file_%lu", version);
		assert((size_t)ret < sizeof(namebuf));

		struct fbr_path_name filename;

		fbr_path_name_init(&filename, namebuf);
		(void)fbr_file_alloc(fs, root, &filename, S_IFREG | 0444);

		fbr_sleep_ms(random() % 50);

		if (do_error) {
			fbr_directory_set_state(fs, root, FBR_DIRSTATE_ERROR);
		} else {
			fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);
		}

		fbr_sleep_ms(1);

		fbr_dindex_release(fs, &root);
	}

	return NULL;
}

void
fbr_cmd_fs_test_root_parallel(struct fbr_test_context *ctx,
    struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_test_random_seed();

	struct fbr_fs *fs = fbr_fs_alloc();
	fbr_fs_ok(fs);

	fs->log = fbr_fs_test_logger;

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_test_ASSERT(fs->root, "fs->root is missing");

	pthread_t threads[_TEST_DIR_THREADS];

	for (size_t i = 0; i < _TEST_DIR_THREADS; i++) {
		assert_zero(pthread_create(&threads[i], NULL, _root_parallel, fs));
	}

	if (random() % 8) {
		fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);
	} else {
		fbr_directory_set_state(fs, root, FBR_DIRSTATE_ERROR);
	}

	fbr_dindex_release(fs, &root);

	for (size_t i = 0; i < _TEST_DIR_THREADS; i++) {
		assert_zero(pthread_join(threads[i], NULL));
	}

	fbr_test_log(ctx, FBR_LOG_VERY_VERBOSE, "root parallel threads exited");

	fbr_fs_release_all(fs, 1);

	fbr_fs_test_stats(fs);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_fs_free(fs);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "root parallel test done");
}
