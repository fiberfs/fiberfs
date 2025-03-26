/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "core/fs/fbr_fs.h"
#include "sys/fbr_sys.h"

#include "test/fbr_test.h"

#define _DSTORE_CHUNK_PATH			"chunks"
#define _DSTORE_META_PATH			"meta"

struct {
	unsigned int				magic;
#define _DSTORE_MAGIC				0x1B775C3C

	const char				*root;

	pthread_mutex_t				open_lock;
} __DSTORE, *_DSTORE;

#define fbr_dstore_ok()				fbr_magic_check(_DSTORE, _DSTORE_MAGIC)

static void
_dstore_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_dstore_ok();

	pt_assert(pthread_mutex_destroy(&_DSTORE->open_lock));

	fbr_ZERO(&_DSTORE);
}

void
fbr_dstore_init(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	assert_zero(_DSTORE);
	assert_zero(__DSTORE.magic);

	__DSTORE.magic = _DSTORE_MAGIC;
	__DSTORE.root = fbr_test_mkdir_tmp(ctx, NULL);

	pt_assert(pthread_mutex_init(&__DSTORE.open_lock, NULL));

	_DSTORE = &__DSTORE;

	fbr_dstore_ok();

	fbr_test_register_finish(ctx, "dstore", _dstore_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "dstore root: %s", _DSTORE->root);
}

static void
_dstore_mkdirs(char *path)
{
	assert(path);

	size_t path_len = strlen(path);

	for (size_t i = 1; i < path_len; i++) {
		if (path[i] == '/') {
			path[i] = '\0';

			int ret = mkdir(path, S_IRWXU);
			fbr_ASSERT(!ret || errno == EEXIST, "mkdir error %s %d", path, errno);

			path[i] = '/';
		}
	}
}

static int
_dstore_open(const char *path)
{
	assert(path);

	pt_assert(pthread_mutex_lock(&_DSTORE->open_lock));

	fbr_ASSERT(!fbr_sys_exists(path), "chunk exists: %s", path);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	assert(fd >= 0);

	pt_assert(pthread_mutex_unlock(&_DSTORE->open_lock));

	return fd;
}

void
fbr_dstore_wbuffer(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(wbuffer);

	char buf[PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buf, sizeof(buf));

	fbr_test_logs("DSTORE wbuffer file: '%s'", filepath.name);

	fbr_id_t id = wbuffer->id;
	char chunk_id[FBR_ID_STRING_MAX];
	fbr_id_string(id, chunk_id, sizeof(chunk_id));

	while (wbuffer) {
		assert(wbuffer->id == id);

		char chunk_path[PATH_MAX];
		size_t ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s/%s.%s.%zu",
			_DSTORE->root,
			_DSTORE_CHUNK_PATH,
			filepath.name,
			chunk_id,
			wbuffer->offset);
		assert(ret < sizeof(chunk_path));

		fbr_test_logs("DSTORE wbuffer chunk: '%s'", chunk_path);

		_dstore_mkdirs(chunk_path);

		int fd = _dstore_open(chunk_path);

		size_t bytes = 0;
		while (bytes < wbuffer->end) {
			ssize_t ret = write(fd, wbuffer->buffer + bytes, wbuffer->end - bytes);
			assert(ret > 0);

			bytes += ret;
		}
		assert(bytes == wbuffer->end);

		ret = close(fd);
		assert_zero(ret);

		fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);

		wbuffer = wbuffer->next;
	}
}

static void
_dstore_chunk(struct fbr_file *file, struct fbr_chunk *chunk, enum fbr_chunk_state state)
{
	assert_dev(file);
	assert_dev(chunk);
	assert(state);

	if (chunk->state == FBR_CHUNK_EMPTY) {
		chunk->state = state;
		return;
	}

	fbr_chunk_update(&file->body, chunk, state);
}

void
fbr_dstore_fetch(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);

	char buf[PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buf, sizeof(buf));

	fbr_test_logs("DSTORE fetch file: '%s'", filepath.name);

	char chunk_id[FBR_ID_STRING_MAX];
	fbr_id_string(chunk->id, chunk_id, sizeof(chunk_id));

	char chunk_path[PATH_MAX];
	size_t ret = snprintf(chunk_path, sizeof(chunk_path), "%s/%s/%s.%s.%zu",
		_DSTORE->root,
		_DSTORE_CHUNK_PATH,
		filepath.name,
		chunk_id,
		chunk->offset);
	assert(ret < sizeof(chunk_path));

	fbr_test_logs("DSTORE fetch chunk: '%s'", chunk_path);

	int fd = open(chunk_path, O_RDONLY);

	if (fd < 0) {
		fbr_test_logs("DSTORE fetch chunk open() error");
		_dstore_chunk(file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	struct stat st;
	ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_test_logs("DSTORE fetch chunk size error");
		_dstore_chunk(file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	size_t bytes = 0;
	while (bytes < chunk->length) {
		ssize_t ret = read(fd, chunk->data + bytes, chunk->length - bytes);
		if (ret <= 0) {
			assert_zero(close(fd));
			_dstore_chunk(file, chunk, FBR_CHUNK_EMPTY);
			return;
		}

		bytes += ret;
	}
	assert(bytes == chunk->length);

	ret = close(fd);
	assert_zero(ret);

	_dstore_chunk(file, chunk, FBR_CHUNK_READY);

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, bytes);
}
