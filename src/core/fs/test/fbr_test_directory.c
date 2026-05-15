/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define FBR_TEST_FILE

#include <pthread.h>
#include <stdlib.h>

#include "core/fs/fbr_fs.h"
#include "cstore/fbr_cstore_api.h"

#include "test/fbr_test.h"
#include "fbr_test_fs_cmds.h"
#include "config/test/fbr_test_config_cmds.h"
#include "core/fuse/test/fbr_test_fuse_cmds.h"
#include "cstore/test/fbr_test_cstore_cmds.h"

#define _TEST_DIR_THREADS_ALLOC		3
#define _TEST_DIR_THREADS_READ		3
#define _TEST_DIR_THREADS_RELEASE	2
#define _TEST_DIR_RELEASES		4
#define _TEST_DIR_MAX_TIME		2.0

static int _TEST_ROOT;
static fbr_inode_t _TEST_INODE;
static unsigned long _TEST_DIR_THREAD;
static unsigned long _TEST_DIR_GENERATION;

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
		fbr_bprintf(namebuf, "file_%lu", generation);

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
	struct fbr_fs *fs = fbr_test_fs_mock(NULL);

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
	struct fbr_fs *fs = fbr_test_fs_mock(NULL);
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

	fbr_test_logs("*** directories (pre wait): %zu", fs->stats.directories);

	fbr_test_fs_wait(fs);

	fbr_test_logs("*** directories: %zu", fs->stats.directories);

	if (ttl) {
		assert(fs->stats.directories == 1);
	} else {
		assert(fs->stats.directories == 101);
	}

	fbr_test_logs("*** releasing dir1");

	fbr_dindex_release(fs, &dir1);

	fbr_test_logs("*** directories (pre wait): %zu", fs->stats.directories);

	fbr_test_fs_wait(fs);

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

#define _LOAD_TTL_THREADS	4
static size_t _LOAD_TTL_THREAD_COUNT;
static size_t _LOAD_TTL_GEN_STOP;
static fbr_stats_t _LOAD_TTL_GEN_HITS[32];

static void *
_directory_load_thread(void *arg)
{
	assert(arg);

	struct fbr_fs *fs = arg;
	fbr_fs_ok(fs);

	size_t thread_id = fbr_atomic_add(&_LOAD_TTL_THREAD_COUNT, 1);

	fbr_test_logs("*** thread %zu running", thread_id);

	while (_LOAD_TTL_THREAD_COUNT < _LOAD_TTL_THREADS) {
		fbr_sleep_ms(0.1);
	}
	assert(_LOAD_TTL_THREAD_COUNT == _LOAD_TTL_THREADS);

	unsigned long generation;

	do {
		struct fbr_directory *directory = fbr_directory_from_inode(fs, FBR_INODE_ROOT);
		fbr_directory_ok(directory);
		assert(directory->generation);

		generation = directory->generation;

		fbr_dindex_release(fs, &directory);

		fbr_stat_add(&_LOAD_TTL_GEN_HITS[generation - 1]);

		long sleep = fbr_test_gen_random(0, 20);
		fbr_test_sleep_ms(sleep);
	} while (generation < _LOAD_TTL_GEN_STOP);

	return NULL;
}

static unsigned long
_directory_load_bump(struct fbr_fs *fs, unsigned long generation)
{
	fbr_fs_ok(fs);
	assert(generation);

	struct fbr_directory *directory = fbr_directory_root_alloc(fs);
	fbr_directory_ok(directory);
	fbr_directory_ok(directory->previous);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	assert(directory->previous->generation);
	fbr_directory_copy(fs, directory, directory->previous);
	assert(directory->generation = generation);

	generation++;
	directory->generation = generation;

	fbr_test_logs("*** writing generation %lu", directory->generation);

	fbr_test_fs_write_index(fs, directory);
	fbr_dindex_release(fs, &directory);

	return generation;
}

static void
_directory_load_ttl(struct fbr_test_context *ctx)
{
	assert_zero(_LOAD_TTL_THREAD_COUNT);
	assert(_LOAD_TTL_GEN_STOP);
	assert(_LOAD_TTL_GEN_STOP <= fbr_array_len(_LOAD_TTL_GEN_HITS));

	fbr_test_fuse_mock(ctx);

	fbr_test_logs("*** init fs_read fs_write");

	struct fbr_cstore *cstore_proxy = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(cstore_proxy);
	assert(fbr_test_cstore_get(ctx, 0) == cstore_proxy);

	struct fbr_cstore *cstore_s3 = fbr_test_cstore_init(ctx);
	fbr_cstore_ok(cstore_s3);
	fbr_test_cstore_s3_mock(cstore_s3, NULL, "region", "key", "secret");
	assert(fbr_test_cstore_get(ctx, 1) == cstore_s3);
	fbr_test_cstore_backend_add(cstore_proxy, cstore_s3, FBR_CSTORE_ROUTE_S3);

	struct fbr_fs *fs_read = fbr_test_fs_alloc();
	fbr_fs_ok(fs_read);
	fbr_test_cstore_bind_new(fs_read);
	fbr_fs_set_store(fs_read, FBR_CSTORE_DEFAULT_CALLBACKS);
	fbr_test_cstore_backend_add(fs_read->cstore, cstore_proxy, FBR_CSTORE_ROUTE_CDN);
	fbr_test_cstore_backend_add(fs_read->cstore, cstore_s3, FBR_CSTORE_ROUTE_S3);

	struct fbr_fs *fs_write = fbr_test_fs_alloc();
	fbr_fs_ok(fs_write);
	fbr_test_cstore_bind(fs_write, 1);
	fbr_fs_set_store(fs_write, FBR_CSTORE_DEFAULT_CALLBACKS);

	fbr_test_logs("*** init root");

	double time_start = fbr_get_time();

	fbr_test_fs_root_alloc(fs_write);
	struct fbr_directory *root = fbr_directory_load(fs_read, FBR_DIRNAME_ROOT,
		FBR_INODE_ROOT, 0);
	fbr_directory_ok(root);
	unsigned long generation = root->generation;
	assert(generation == 1);
	fbr_dindex_release(fs_read, &root);

	fbr_test_logs("*** creating threads");

	pthread_t threads[_LOAD_TTL_THREADS];

	for (size_t i = 0; i < _LOAD_TTL_THREADS; i++) {
		pt_assert(pthread_create(&threads[i], NULL, _directory_load_thread, fs_read));
	}

	fbr_test_logs("*** threads created: %d", _LOAD_TTL_THREADS);

	while (generation < _LOAD_TTL_GEN_STOP) {
		if (!_LOAD_TTL_GEN_HITS[generation - 1]) {
			fbr_test_sleep_ms(1);
			continue;
		}

		generation = _directory_load_bump(fs_write, generation);
	}

	fbr_test_logs("*** joining threads....");

	for (size_t i = 0; i < fbr_array_len(threads); i++) {
		pt_assert(pthread_join(threads[i], NULL));
	}

	fbr_test_logs("*** all threads joined");

	double time_end = fbr_get_time();

	for (size_t i = 0; i < _LOAD_TTL_GEN_STOP; i++) {
		fbr_test_logs("root generation %zu hits: %lu", i + 1, _LOAD_TTL_GEN_HITS[i]);
	}

	fbr_test_logs("time: %lf", time_end - time_start);

	fbr_test_logs("*** cleanup fs_read");

	fbr_fs_release_all(fs_read, 1);
	fbr_test_fs_stats(fs_read);
	assert_zero(fs_read->stats.directories);
	assert_zero(fs_read->stats.directories_dindex);
	assert_zero(fs_read->stats.directory_refs);
	assert_zero(fs_read->stats.files);
	assert_zero(fs_read->stats.files_inodes);
	assert_zero(fs_read->stats.file_refs);
	if (!fbr_test_is_valgrind()) {
		assert(fs_read->stats.index_loads == _LOAD_TTL_GEN_STOP);
		assert(fs_read->stats.directories_total - fs_read->stats.dir_alloc_hit ==
			_LOAD_TTL_GEN_STOP)
	}
	fbr_fs_free(fs_read);

	fbr_test_logs("*** cleanup fs_write");

	fbr_fs_release_all(fs_write, 1);
	fbr_test_fs_wait(fs_write);
	assert_zero(fs_write->stats.directories);
	assert_zero(fs_write->stats.directories_dindex);
	assert_zero(fs_write->stats.directory_refs);
	assert_zero(fs_write->stats.files);
	assert_zero(fs_write->stats.files_inodes);
	assert_zero(fs_write->stats.file_refs);
	fbr_fs_free(fs_write);

	fbr_test_logs("CSTORE_DEBUG cstore_proxy");
	fbr_test_cstore_debug(cstore_proxy);
	if (!fbr_test_is_valgrind()) {
		assert(cstore_proxy->stats.http_200 == _LOAD_TTL_GEN_STOP * 2);
		assert_zero(cstore_proxy->stats.http_400);
		assert_zero(cstore_proxy->stats.http_500);
		assert_zero(cstore_proxy->stats.http_other);
	}

	fbr_test_logs("CSTORE_DEBUG cstore_s3");
	fbr_test_cstore_debug(cstore_s3);
	assert(cstore_s3->entries == 2);
	if (!fbr_test_is_valgrind()) {
		assert(cstore_s3->stats.http_200 == _LOAD_TTL_GEN_STOP * 2);
		assert_zero(cstore_s3->stats.http_400);
		assert_zero(cstore_s3->stats.http_500);
		assert_zero(cstore_s3->stats.http_other);
	}
}

void
fbr_cmd_fs_test_directory_load_ttl(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	assert(FBR_CSTORE_ROOT_TTL_MIN < FBR_ROOT_TTL_MIN);

	fbr_test_conf_add("LOG_SIZE", "200000");
	fbr_test_conf_add("ASYNC_WRITE", "false");
	fbr_test_conf_add("CSTORE_SERVER", "true");
	fbr_test_conf_add("CSTORE_SERVER_ADDRESS", "127.0.0.1");
	fbr_test_conf_add("CSTORE_SERVER_PORT", "0");
	fbr_test_conf_add("ROOT_FILE_TTL_SEC", "0");

	_LOAD_TTL_GEN_STOP = 5;

	fbr_test_random_seed();

	_directory_load_ttl(ctx);

	fbr_test_logs("directory_load_ttl done");
}
