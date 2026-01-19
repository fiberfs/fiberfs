/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#define _DEFAULT_SOURCE

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_cstore_api.h"
#include "core/request/fbr_request.h"
#include "utils/fbr_sys.h"

static void *_cstore_load_thread(void *arg);

void
fbr_cstore_loader_init(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_loader *loader = &cstore->loader;
	fbr_zero(loader);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath_data(cstore, 0, &hashpath);
	if (!fbr_sys_isdir(hashpath.value)) {
		loader->state = FBR_CSTORE_LOADER_DONE;
		return;
	}

	loader->state = FBR_CSTORE_LOADER_READING;
	loader->start_time = fbr_get_time() - FBR_CSTORE_LOAD_TIME_BUFFER;
	loader->thread_count = _CSTORE_CONFIG.loader_threads;
	assert(loader->thread_count);

	if (loader->thread_count > FBR_CSTORE_LOAD_THREAD_MAX) {
		loader->thread_count = FBR_CSTORE_LOAD_THREAD_MAX;
	}
	while (256 % loader->thread_count) {
		loader->thread_count--;
	}

	for (size_t i = 0; i < loader->thread_count; i++) {
		pt_assert(pthread_create(&loader->threads[i], NULL, _cstore_load_thread,
			cstore));
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_LOADER, FBR_REQID_CSTORE,
		"spawned %zu loader threads", loader->thread_count);
}

static void
_cstore_remove(const char *hpath, const char *file)
{
	assert_dev(hpath);
	assert_dev(file);

	char filepath[FBR_PATH_MAX];
	fbr_bprintf(filepath, "%s/%s", hpath, file);

	(void)unlink(filepath);
}

static size_t
_cstore_scan_dir(struct fbr_cstore *cstore, const char *hpath, unsigned char h1, int h2)
{
	assert_dev(cstore);
	assert_dev(hpath);

	DIR *dir = opendir(hpath);
	if (!dir) {
		return 0;
	}

	struct dirent *dentry;
	char subpath[FBR_PATH_MAX];
	size_t insertions = 0;
	int subdir = 1;
	if (h2 >= 0) {
		assert(h2 < 256);
		subdir = 0;
	}

	while ((dentry = readdir(dir)) != NULL) {
		if (!strcmp(dentry->d_name, ".") || !strcmp(dentry->d_name, "..")) {
			continue;
		}

		if (subdir == 1) {
			if (dentry->d_type != DT_DIR || strlen(dentry->d_name) != 2) {
				_cstore_remove(hpath, dentry->d_name);
				continue;
			}

			unsigned char hash;
			size_t hash_len = fbr_hex2bin(dentry->d_name, 2, &hash, sizeof(hash));
			assert(hash_len == 1);

			fbr_bprintf(subpath, "%s/%s", hpath, dentry->d_name);

			insertions += _cstore_scan_dir(cstore, subpath, h1, hash);

			continue;
		}

		if (dentry->d_type != DT_REG || strlen(dentry->d_name) != 12) {
			_cstore_remove(hpath, dentry->d_name);
			continue;
		}

		struct stat st;
		int ret = lstat(hpath, &st);
		if (ret || st.st_size <= 0) {
			_cstore_remove(hpath, dentry->d_name);
			continue;
		}

		assert_dev(cstore->loader.start_time);
		double modified = fbr_convert_timespec(&st.st_mtim);
		if (modified > cstore->loader.start_time) {
			continue;
		}

		fbr_hash_t hash;
		char *hash_buf = (char*)&hash;
		size_t hash_len = fbr_hex2bin(dentry->d_name, 12, hash_buf + 2, sizeof(hash) - 2);
		assert(hash_len + 2 == sizeof(hash));
		hash_buf[0] = h1;
		hash_buf[1] = (unsigned char)h2;

		struct fbr_cstore_entry *centry = fbr_cstore_insert(cstore, hash, st.st_size, 0);
		if (centry) {
			fbr_cstore_entry_ok(centry);
			assert_dev(centry->state == FBR_CSTORE_OK);

			fbr_atomic_add(&cstore->stats.loaded, 1);
			insertions++;

			fbr_cstore_release(cstore, centry);
		}
	}

	closedir(dir);

	return insertions;
}

static void *
_cstore_load_thread(void *arg)
{
	assert(arg);

	struct fbr_cstore *cstore = arg;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_loader *loader = &cstore->loader;
	size_t pos = fbr_atomic_add(&loader->thread_pos, 1);
	size_t thread_id = fbr_request_id_thread_gen();
	size_t dir_count = 256 / loader->thread_count;
	size_t dir_start = (pos - 1) * dir_count;
	size_t dir_end = dir_start + dir_count - 1;
	assert_dev(dir_end < 256);

	size_t insertions = 0;

	// If testing, randomly delay the loader a bit
	if (fbr_is_test()) {
		if (random() % 3 == 0) {
			fbr_sleep_ms(250);
		}
	}

	while (!loader->stop && dir_start <= dir_end) {
		assert_dev(dir_start < 256);
		unsigned char dir = dir_start;

		struct fbr_cstore_hashpath hashpath;
		fbr_cstore_hashpath_loader(cstore, dir, 0, &hashpath);

		insertions += _cstore_scan_dir(cstore, hashpath.value, dir, -1);

		dir_start++;
	}

	if (insertions) {
		fbr_log_print(cstore->log, FBR_LOG_CS_LOADER, thread_id,
			"thread %zu inserted: %zu", pos, insertions);
		}

	size_t count = fbr_atomic_add(&loader->thread_done, 1);
	if (count == loader->thread_count) {
		assert_dev(loader->state == FBR_CSTORE_LOADER_READING);
		loader->state = FBR_CSTORE_LOADER_DONE;

		double time_spent = fbr_get_time() - loader->start_time;
		fbr_log_print(cstore->log, FBR_LOG_CS_LOADER, thread_id, "COMPLETED "
			"loaded: %zu lazy: %lu time: %.3fs",
			cstore->stats.loaded, cstore->stats.lazy_loaded, time_spent);

		// TODO cleanup metadata here ?
	}

	return NULL;
}

void
fbr_cstore_loader_free(struct fbr_cstore *cstore)
{
	fbr_cstore_ok(cstore);

	struct fbr_cstore_loader *loader = &cstore->loader;

	loader->stop = 1;

	for (size_t i = 0; i < loader->thread_count; i++) {
		pt_assert(pthread_join(loader->threads[i], NULL));
	}

	assert(loader->thread_pos == loader->thread_count);
	assert_dev(loader->thread_done == loader->thread_count);
	assert_dev(loader->state == FBR_CSTORE_LOADER_DONE);

	fbr_zero(loader);
}
