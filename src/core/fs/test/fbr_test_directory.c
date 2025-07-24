/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
#include <stdlib.h>

#include "core/fs/fbr_fs.h"

#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"

#define _TEST_DIR_THREADS_ALLOC		3
#define _TEST_DIR_THREADS_READ		3
#define _TEST_DIR_THREADS_RELEASE	2
#define _TEST_DIR_RELEASES		4
#define _TEST_DIR_MAX_TIME		2.0

int _TEST_ROOT;
fbr_inode_t _TEST_INODE;
unsigned long _TEST_DIR_THREAD;
unsigned long _TEST_DIR_GENERATION;

static void *
_dir_test_alloc(void *arg)
{
	struct fbr_fs *fs = (struct fbr_fs*)arg;
	fbr_fs_ok(fs);

	unsigned long id = fbr_atomic_add(&_TEST_DIR_THREAD, 1);

	fbr_test_logs("alloc thread_%lu: started", id);

	double time_start = fbr_get_time();

	while (fbr_get_time() - time_start < _TEST_DIR_MAX_TIME) {
		struct fbr_directory *directory = NULL;

		if (_TEST_ROOT) {
			directory = fbr_directory_root_alloc(fs);
		} else {
			assert(_TEST_INODE > FBR_INODE_ROOT);

			if (random() % 4 == 0) {
				struct fbr_directory *root = fbr_directory_root_alloc(fs);
				fbr_directory_ok(root);
				assert(root->inode == FBR_INODE_ROOT);

				if (root->state != FBR_DIRSTATE_LOADING) {
					fbr_dindex_release(fs, &root);
					fbr_sleep_ms(1);
					continue;
				}

				struct fbr_path_name filename;
				fbr_path_name_init(&filename, "random");

				struct fbr_file *file =
					fbr_file_alloc(fs, root, &filename);
				assert(file->parent_inode == root->inode);
				assert(file->inode > _TEST_INODE);
				file->mode = S_IFDIR;
				file->state = FBR_FILE_OK;

				_TEST_INODE = file->inode;

				fbr_inode_add(fs, file);

				fbr_test_logs("INODE=%lu", file->inode);

				fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

				fbr_dindex_release(fs, &root);

				directory = fbr_directory_alloc(fs, &filename, file->inode);

				fbr_inode_release(fs, &file);
			} else {
				fbr_inode_t inode = _TEST_INODE;

				struct fbr_file *file = fbr_inode_take(fs, inode);

				if (!file) {
					continue;
				}
				fbr_file_ok(file);

				struct fbr_path_name filename;
				fbr_path_name_init(&filename, "random");

				directory = fbr_directory_alloc(fs, &filename, inode);

				fbr_inode_release(fs, &file);
			}
		}

		fbr_directory_ok(directory);

		if (directory->state == FBR_DIRSTATE_OK) {
			fbr_sleep_ms(random() % 20);
			fbr_dindex_release(fs, &directory);
			fbr_sleep_ms(1);
			continue;
		} else if (directory->state == FBR_DIRSTATE_ERROR) {
			fbr_test_logs("alloc thread_%lu: got ERROR inode: %lu", id,
				directory->inode);
			fbr_dindex_release(fs, &directory);
			fbr_sleep_ms(1);
			continue;
		}

		assert(directory->state == FBR_DIRSTATE_LOADING);

		unsigned long generation = fbr_atomic_add(&_TEST_DIR_GENERATION, 1);
		int do_error = (random() % 3 == 0);

		directory->generation = generation;

		unsigned long diff_ms = (long)((fbr_get_time() - time_start) * 1000);

		fbr_test_logs("alloc thread_%lu (+%ld): inode: %lu(%lu) error: %d "
				"previous: %s previous_inode: %lu(%lu)",
			id, diff_ms, directory->inode, generation, do_error,
			directory->previous ? "true" : "false",
			directory->previous ? directory->previous->inode : 0,
			directory->previous ? directory->previous->generation: 0);

		char namebuf[128];
		ssize_t ret = snprintf(namebuf, sizeof(namebuf), "file_%lu", generation);
		assert((size_t)ret < sizeof(namebuf));

		struct fbr_path_name filename;

		fbr_path_name_init(&filename, namebuf);
		struct fbr_file *file = fbr_file_alloc(fs, directory, &filename);
		file->mode = S_IFREG | 0444;
		file->state = FBR_FILE_OK;

		if (directory->previous && !(random() % 2)) {
			struct fbr_directory *previous = directory->previous;
			fbr_directory_ok(previous);
			assert(previous->state == FBR_DIRSTATE_OK);

			struct fbr_file_ptr *file_ptr;

			RB_FOREACH(file_ptr, fbr_filename_tree, &previous->filename_tree) {
				fbr_file_ptr_ok(file_ptr);
				file = file_ptr->file;

				fbr_path_get_file(&file->path, &filename);
				fbr_test_logs("carry over: %s (%lu(%lu) => %lu(%lu))"
					" refcount: %u+%u",
					filename.name,
					previous->inode, previous->generation,
					directory->inode, directory->generation,
					file->refcounts.dindex, file->refcounts.inode);

				fbr_directory_add_file(fs, directory, file);
			}
		}

		fbr_sleep_ms(random() % 50);

		if (do_error) {
			fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
		} else {
			fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
		}

		fbr_sleep_ms(random() % 10);

		fbr_dindex_release(fs, &directory);
	}

	return NULL;
}

static void *
_dir_test_read(void *arg)
{
	struct fbr_fs *fs = (struct fbr_fs*)arg;
	fbr_fs_ok(fs);

	unsigned long id = fbr_atomic_add(&_TEST_DIR_THREAD, 1);
	unsigned long count = id;

	fbr_test_logs("read thread_%lu: started", id);

	double time_start = fbr_get_time();

	while (fbr_get_time() - time_start < _TEST_DIR_MAX_TIME) {
		struct fbr_path_name dirname;

		if (_TEST_ROOT) {
			fbr_path_name_init(&dirname, "");
		} else {
			assert(_TEST_INODE > FBR_INODE_ROOT);
			fbr_path_name_init(&dirname, "random");
		}

		int wait_for_new = random() % 2;

		struct fbr_directory *directory = fbr_dindex_take(fs, &dirname, wait_for_new);

		if (!directory) {
			continue;
		}

		fbr_directory_ok(directory);

		fbr_dindex_release(fs, &directory);

		fbr_sleep_ms(random() % 5);

		count++;
	}

	return NULL;
}

static void *
_dir_test_release(void *arg)
{
	struct fbr_fs *fs = (struct fbr_fs*)arg;
	fbr_fs_ok(fs);

	unsigned long id = fbr_atomic_add(&_TEST_DIR_THREAD, 1);
	int count = 0;

	fbr_test_logs("release thread_%lu: started", id);

	double time_start = fbr_get_time();

	while (fbr_get_time() - time_start < _TEST_DIR_MAX_TIME) {
		long sleep_time = (long)_TEST_DIR_MAX_TIME * 2000 / _TEST_DIR_RELEASES;
		fbr_sleep_ms(random() % sleep_time);

		fbr_test_logs("release thread_%lu: releasing all!", id);

		fbr_fs_release_all(fs, 0);

		count++;
		if (count == _TEST_DIR_RELEASES) {
			break;
		}
	}

	return NULL;
}

static void
_directory_parallel(void)
{
	struct fbr_fs *fs = fbr_test_fuse_mock_fs(NULL);

	fbr_test_random_seed();

	_TEST_INODE = 0;
	_TEST_DIR_THREAD = 0;
	_TEST_DIR_GENERATION = 0;

	unsigned long generation = fbr_atomic_add(&_TEST_DIR_GENERATION, 1);
	assert(generation == 1);

	struct fbr_directory *directory = NULL;

	struct fbr_directory *root = fbr_directory_root_alloc(fs);
	fbr_directory_ok(root);
	assert(root->state == FBR_DIRSTATE_LOADING);

	if (_TEST_ROOT) {
		directory = root;
	} else {
		struct fbr_path_name filename;
		fbr_path_name_init(&filename, "random");

		struct fbr_file *file = fbr_file_alloc(fs, root, &filename);
		assert(file->parent_inode == root->inode);
		file->mode = S_IFDIR;
		file->state = FBR_FILE_OK;

		fbr_inode_add(fs, file);

		fbr_directory_set_state(fs, root, FBR_DIRSTATE_OK);

		fbr_dindex_release(fs, &root);

		_TEST_INODE = file->inode;

		directory = fbr_directory_alloc(fs, &filename, _TEST_INODE);

		fbr_inode_release(fs, &file);
	}

	fbr_directory_ok(directory);
	directory->generation = generation;

	fbr_test_logs("INODE=%lu", directory->inode);

	pthread_t threads[_TEST_DIR_THREADS_ALLOC + _TEST_DIR_THREADS_READ +
		_TEST_DIR_THREADS_RELEASE];
	size_t pos = 0;

	for (size_t i = 0; i < _TEST_DIR_THREADS_ALLOC; i++, pos++) {
		pt_assert(pthread_create(&threads[pos], NULL, _dir_test_alloc, fs));
	}
	for (size_t i = 0; i < _TEST_DIR_THREADS_READ; i++, pos++) {
		pt_assert(pthread_create(&threads[pos], NULL, _dir_test_read, fs));
	}
	for (size_t i = 0; i < _TEST_DIR_THREADS_RELEASE; i++, pos++) {
		pt_assert(pthread_create(&threads[pos], NULL, _dir_test_release, fs));
	}

	fbr_sleep_ms(3);

	if (random() % 2) {
		fbr_test_logs("main: generation %lu error: 0", generation);
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	} else {
		fbr_test_logs("main: generation %lu error: 1", generation);
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
	}

	fbr_dindex_release(fs, &directory);

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}

	fbr_test_logs("threads exited, releasing all...");

	fbr_fs_release_all(fs, 1);

	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_fs_free(fs);
}

void
fbr_cmd_fs_test_root_parallel(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_TEST_ROOT = 1;

	_directory_parallel();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "root parallel test done");
}

void
fbr_cmd_fs_test_directory_parallel(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_TEST_ROOT = 0;

	_directory_parallel();

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "directory parallel test done");
}

static void
_directory_release(int ttl)
{
	struct fbr_fs *fs = fbr_test_fuse_mock_fs(NULL);
	fbr_fs_ok(fs);

	if (ttl) {
		fbr_test_logs("*** ttl ENABLED");
		fs->config.dentry_ttl = 1000;
	}

	fbr_test_logs("*** alloc root");

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	directory->generation = 1;
	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
	fbr_dindex_release(fs, &directory);

	fbr_test_logs("*** alloc dir1");

	// We hold onto dir1
	struct fbr_directory *dir1 = fbr_directory_root_alloc(fs);
	fbr_directory_ok(dir1);
	fbr_directory_ok(dir1->previous);
	assert(dir1->state == FBR_DIRSTATE_LOADING);
	dir1->generation = dir1->previous->generation + 1;
	fbr_directory_set_state(fs, dir1, FBR_DIRSTATE_OK);

	fbr_test_logs("*** alloc 100 new generations");

	for (size_t i = 0; i < 100; i++) {
		directory = fbr_directory_root_alloc(fs);
		fbr_directory_ok(directory);
		fbr_directory_ok(directory->previous);
		assert(directory->state == FBR_DIRSTATE_LOADING);
		directory->generation = directory->previous->generation + 1;
		assert(directory->generation == i + 3);
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
		fbr_dindex_release(fs, &directory);
	}

	fbr_test_logs("*** releasing all");

	fbr_fs_release_all(fs, 0);

	fbr_test_logs("*** directories: %zu", fs->stats.directories);

	if (ttl) {
		assert(fs->stats.directories == 1);
	} else {
		assert(fs->stats.directories == 101);
	}

	fbr_test_logs("*** releasing dir1");

	fbr_dindex_release(fs, &dir1);

	fbr_test_logs("*** directories: %zu", fs->stats.directories);
	assert_zero(fs->stats.directories);

	fbr_test_logs("*** cleanup");

	fbr_fs_release_all(fs, 1);

	fbr_test_fs_stats(fs);
	fbr_test_fs_inodes_debug(fs);
	fbr_test_fs_dindex_debug(fs);

	fbr_test_ERROR(fs->stats.directories, "non zero");
	fbr_test_ERROR(fs->stats.directories_dindex, "non zero");
	fbr_test_ERROR(fs->stats.directory_refs, "non zero");
	fbr_test_ERROR(fs->stats.files, "non zero");
	fbr_test_ERROR(fs->stats.files_inodes, "non zero");
	fbr_test_ERROR(fs->stats.file_refs, "non zero");

	fbr_fs_free(fs);

	fbr_test_logs("directory release test done (ttl: %d)", ttl);
}

void
fbr_cmd_fs_test_directory_release(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_directory_release(0);
}

void
fbr_cmd_fs_test_directory_release_ttl(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	_directory_release(1);
}
