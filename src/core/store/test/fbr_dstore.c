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

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
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

static void
_dstore_chunk_path(const struct fbr_file *file, fbr_id_t id, size_t offset, int metadata,
    char *buffer, size_t buffer_len)
{
	fbr_dstore_ok();
	assert_dev(file);
	assert(id);
	assert_dev(buffer);
	assert_dev(buffer_len);

	char filebuf[PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, filebuf, sizeof(filebuf));

	char chunk_id[FBR_ID_STRING_MAX];
	fbr_id_string(id, chunk_id, sizeof(chunk_id));

	char *sub_path = _DSTORE_CHUNK_PATH;
	if (metadata) {
		sub_path = _DSTORE_META_PATH;
	}

	size_t ret = snprintf(buffer, buffer_len, "%s/%s/%s.%s.%zu",
		_DSTORE->root,
		sub_path,
		filepath.name,
		chunk_id,
		offset);
	assert(ret < buffer_len);
}

static void
_dstore_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer,
    enum fbr_wbuffer_state state)
{
	assert_dev(fs);
	assert_dev(wbuffer);
	assert(state >= FBR_WBUFFER_DONE);

	if (wbuffer->state == FBR_WBUFFER_READY) {
		wbuffer->state = state;
		return;
	}

	fbr_wbuffer_update(fs, wbuffer, state);
}

void
fbr_dstore_wbuffer(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_dstore_ok();
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);

	char chunk_path[PATH_MAX];
	_dstore_chunk_path(file, wbuffer->id, wbuffer->offset, 0, chunk_path, sizeof(chunk_path));

	fbr_test_logs("DSTORE wbuffer chunk: '%s':%zu", chunk_path, wbuffer->end);

	_dstore_mkdirs(chunk_path);

	int fd = _dstore_open(chunk_path);

	size_t bytes = fbr_sys_write(fd, wbuffer->buffer, wbuffer->end);
	assert(bytes == wbuffer->end);

	assert_zero(close(fd));

	fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);

	_dstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);
}

static void
_dstore_chunk_update(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk,
    enum fbr_chunk_state state)
{
	assert_dev(fs);
	assert_dev(file);
	assert_dev(chunk);
	assert(state == FBR_CHUNK_EMPTY || state == FBR_CHUNK_READY);

	if (chunk->state == FBR_CHUNK_EMPTY) {
		chunk->state = state;
		return;
	}

	fbr_chunk_update(fs, &file->body, chunk, state);
}

void
fbr_dstore_fetch(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_dstore_ok();
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);

	char chunk_path[PATH_MAX];
	_dstore_chunk_path(file, chunk->id, chunk->offset, 0, chunk_path, sizeof(chunk_path));

	fbr_test_logs("DSTORE fetch chunk: '%s'", chunk_path);

	int fd = open(chunk_path, O_RDONLY);

	if (fd < 0) {
		fbr_test_logs("DSTORE fetch chunk open() error");
		_dstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	struct stat st;
	int ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_test_logs("DSTORE fetch chunk size error");
		_dstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		assert_zero(close(fd));
		return;
	}

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	ssize_t bytes = fbr_sys_read(fd, chunk->data, chunk->length);

	if ((size_t)bytes != chunk->length) {
		fbr_test_logs("DSTORE read() error");
		_dstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		assert_zero(close(fd));
		return;
	}

	assert_zero(close(fd));

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, bytes);

	_dstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
}

static void
_dstore_index_path(const struct fbr_directory *directory, int metadata, char *buffer,
    size_t buffer_len)
{
	fbr_dstore_ok();
	assert_dev(directory);
	assert_dev(buffer);
	assert_dev(buffer_len);

	struct fbr_path_name dirpath;
	fbr_path_shared_name(directory->path, &dirpath);

	char version[FBR_ID_STRING_MAX];
	fbr_id_string(directory->version, version, sizeof(version));

	char *sub_path = _DSTORE_CHUNK_PATH;
	if (metadata) {
		sub_path = _DSTORE_META_PATH;
	}

	size_t ret = snprintf(buffer, buffer_len, "%s/%s/%s.fiberfsindex.%s",
		_DSTORE->root,
		sub_path,
		dirpath.name,
		version);
	assert(ret < buffer_len);
}

void
fbr_dstore_index(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(writer);
	assert_dev(writer->final);

	char index_path[PATH_MAX];
	_dstore_index_path(directory, 0, index_path, sizeof(index_path));

	fbr_test_logs("DSTORE index: '%s'", index_path);

	_dstore_mkdirs(index_path);

	int fd = _dstore_open(index_path);

	size_t bytes = 0;

	struct fbr_buffer *final = writer->final;
	while (final) {
		size_t written = fbr_sys_write(fd, final->buffer, final->buffer_pos);
		assert(written == final->buffer_pos);

		bytes += written;

		final = final->next;
	}

	// TODO assert final size

	assert_zero(close(fd));

	//fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);
}
