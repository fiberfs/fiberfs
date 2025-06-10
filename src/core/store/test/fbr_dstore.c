/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <ftw.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_dstore.h"
#include "fjson.h"
#include "compress/fbr_gzip.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "sys/fbr_sys.h"

#include "test/fbr_test.h"

#define _DSTORE_DATA_PATH			"data"
#define _DSTORE_META_PATH			"meta"

struct {
	unsigned int				magic;
#define _DSTORE_MAGIC				0x1B775C3C

	const char				*root;

	pthread_mutex_t				lock;
} __DSTORE, *_DSTORE;

struct _dstore_metadata {
	fbr_id_t				etag;
	unsigned long				size;
	int					gzipped;
	char					_context;
};

#define fbr_dstore_ok()				fbr_magic_check(_DSTORE, _DSTORE_MAGIC)

static void
_dstore_finish(struct fbr_test_context *ctx)
{
	fbr_test_context_ok(ctx);
	fbr_dstore_ok();

	pt_assert(pthread_mutex_destroy(&_DSTORE->lock));

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

	pt_assert(pthread_mutex_init(&__DSTORE.lock, NULL));

	_DSTORE = &__DSTORE;

	fbr_dstore_ok();

	fbr_test_register_finish(ctx, "dstore", _dstore_finish);

	fbr_test_log(ctx, FBR_LOG_VERBOSE, "dstore root: %s", _DSTORE->root);

	fbr_test_random_seed();
}

static void
_dstore_LOCK()
{
	fbr_dstore_ok();
	pt_assert(pthread_mutex_lock(&_DSTORE->lock));
}

static void
_dstore_UNLOCK()
{
	fbr_dstore_ok();
	pt_assert(pthread_mutex_unlock(&_DSTORE->lock));
}

static int
_dstore_debug_cb(const char *filename, const struct stat *stat, int flag, struct FTW *info)
{
	(void)stat;
	(void)info;

	switch (flag) {
		case FTW_F:
		case FTW_SL:
			fbr_test_logs("DSTORE_DEBUG file: %s", filename);
			break;
		default:
			break;
	}

	return 0;
}

void
fbr_dstore_debug(int show_meta)
{
	fbr_dstore_ok();

	if (show_meta) {
		fbr_sys_nftw(_DSTORE->root, _dstore_debug_cb);
		return;
	}

	char path[PATH_MAX];
	size_t ret = snprintf(path, sizeof(path), "%s/%s",
		_DSTORE->root,
		_DSTORE_DATA_PATH);
	assert(ret < sizeof(path));

	fbr_sys_nftw(path, _dstore_debug_cb);
}

void
fbr_cmd_dstore_debug(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd)
{
	fbr_test_context_ok(ctx);
	fbr_test_ERROR_param_count(cmd, 0);

	fbr_dstore_debug(0);
}

static void
_dstore_mkdirs(char *path)
{
	assert(path);

	size_t path_len = strlen(path);
	assert(path_len < PATH_MAX);

	for (size_t i = 1; i < path_len; i++) {
		if (path[i] == '/') {
			path[i] = '\0';

			int ret = mkdir(path, S_IRWXU);
			fbr_ASSERT(!ret || errno == EEXIST, "mkdir error %s %d", path, errno);

			path[i] = '/';
		}
	}
}

// If-None-Match: *
static int
_dstore_open_unique(const char *path)
{
	assert(path);

	_dstore_LOCK();

	fbr_ASSERT(!fbr_sys_exists(path), "chunk exists: %s", path);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	assert(fd >= 0);

	_dstore_UNLOCK();

	return fd;
}

static void
_dstore_writer(int fd, struct fbr_writer *writer)
{
	assert_dev(fd >= 0);
	assert_dev(writer);

	size_t bytes = 0;

	struct fbr_buffer *output = writer->output;
	while (output) {
		fbr_buffer_ok(output);

		if (output->buffer_pos) {
			size_t written = fbr_sys_write(fd, output->buffer, output->buffer_pos);
			assert(written == output->buffer_pos);

			bytes += written;
		}

		output = output->next;
	}

	assert(bytes == writer->bytes);
}

static void
_dstore_metadata_write(char *path, struct _dstore_metadata *metadata)
{
	assert_dev(path);
	assert_dev(metadata);

	_dstore_mkdirs(path);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

	// e: etag
	char buf[FBR_ID_STRING_MAX];
	fbr_id_string(metadata->etag, buf, sizeof(buf));

	fbr_sys_write(fd, "{\"e\":\"", 6);
	fbr_sys_write(fd, buf, strlen(buf));

	// s: size
	int ret = snprintf(buf, sizeof(buf), "%lu", metadata->size);
	assert(ret > 0 && (size_t)ret < sizeof(buf));

	fbr_sys_write(fd, "\",\"s\":", 6);
	fbr_sys_write(fd, buf, strlen(buf));

	// g: gzipped
	fbr_sys_write(fd, ",\"g\":", 5);

	if (metadata->gzipped) {
		fbr_sys_write(fd, "1}", 2);
	} else {
		fbr_sys_write(fd, "0}", 2);
	}

	assert_zero(close(fd));
}

static int
_json_parse(struct fjson_context *ctx, void *priv)
{
	fjson_context_ok(ctx);
	assert(priv);

	struct _dstore_metadata *metadata = (struct _dstore_metadata*)priv;

	struct fjson_token *token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	assert_dev(ctx->tokens_pos >= 2);
	size_t depth = ctx->tokens_pos - 2;

	if (token->type == FJSON_TOKEN_OBJECT) {
		if (depth != 0) {
			return 1;
		}
		if (token->closed && token->length != 3) {
			return 1;
		}
		return 0;
	}
	if (token->type == FJSON_TOKEN_LABEL) {
		if (depth != 1 || token->svalue_len != 1) {
			return 1;
		}
		metadata->_context = token->svalue[0];
		return 0;
	}
	if (token->type == FJSON_TOKEN_STRING && metadata->_context == 'e') {
		if (depth != 2) {
			return 1;
		}
		metadata->etag = fbr_id_parse(token->svalue, token->svalue_len);
		metadata->_context = '\0';
		return 0;
	}
	if (token->type == FJSON_TOKEN_NUMBER) {
		if (depth != 2) {
			return 1;
		}
		if (metadata->_context == 's') {
			if (token->dvalue < 0) {
				return 1;
			}
			metadata->size = (size_t)token->dvalue;
		} else if (metadata->_context == 'g') {
			if (token->dvalue != 0 && token->dvalue != 1) {
				return 1;
			}
			metadata->gzipped = (int)token->dvalue;
		} else {
			return 1;
		}
		metadata->_context = '\0';
		return 0;
	}

	return 1;
}

static void
_dstore_metadata_read(const char *path, struct _dstore_metadata *metadata)
{
	assert_dev(path);
	assert_dev(metadata);

	fbr_ZERO(metadata);

	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		fbr_test_logs("DSTORE metadata open(%s) error %d %d %s", path, fd, errno,
			strerror(errno));
		return;
	}

	char buffer[1024];

	ssize_t bytes = fbr_sys_read(fd, buffer, sizeof(buffer));
	assert(bytes > 0 && (size_t)bytes < sizeof(buffer) - 1);

	assert_zero(close(fd));

	buffer[bytes] = '\0';

	struct fjson_context json;
	fjson_context_init(&json);
	json.callback = &_json_parse;
	json.callback_priv = metadata;

	fjson_parse(&json, buffer, bytes);
	fbr_ASSERT(!json.error, "JSON error");

	fjson_context_free(&json);
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

	char *sub_path = _DSTORE_DATA_PATH;
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
fbr_dstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_dstore_ok();
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	char chunk_path[PATH_MAX];
	_dstore_chunk_path(file, wbuffer->id, wbuffer->offset, 0, chunk_path, sizeof(chunk_path));

	fbr_test_logs("DSTORE wbuffer chunk: '%s':%zu", chunk_path, wbuffer->end);

	_dstore_mkdirs(chunk_path);

	int fd = _dstore_open_unique(chunk_path);

	size_t bytes = fbr_sys_write(fd, wbuffer->buffer, wbuffer->end);
	assert(bytes == wbuffer->end);

	assert_zero(close(fd));

	struct _dstore_metadata metadata;
	fbr_ZERO(&metadata);
	metadata.etag = wbuffer->id;
	metadata.size = wbuffer->end;

	_dstore_chunk_path(file, wbuffer->id, wbuffer->offset, 1, chunk_path, sizeof(chunk_path));
	_dstore_metadata_write(chunk_path, &metadata);

	fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);
	fbr_fs_stat_add(&fs->stats.store_chunks);

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

	fbr_chunk_update(fs, file, chunk, state);
}

void
fbr_dstore_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_dstore_ok();
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->id);
	assert(chunk->state == FBR_CHUNK_EMPTY);

	char chunk_path[PATH_MAX];
	_dstore_chunk_path(file, chunk->id, chunk->offset, 0, chunk_path, sizeof(chunk_path));

	fbr_test_logs("DSTORE read chunk: '%s'", chunk_path);

	int fd = open(chunk_path, O_RDONLY);

	if (fd < 0) {
		fbr_test_logs("DSTORE read chunk open() error");
		_dstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	struct stat st;
	int ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_test_logs("DSTORE read chunk size error");
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

	struct _dstore_metadata metadata;
	_dstore_chunk_path(file, chunk->id, chunk->offset, 1, chunk_path, sizeof(chunk_path));
	_dstore_metadata_read(chunk_path, &metadata);

	fbr_ASSERT(metadata.etag == chunk->id, "%lu != %lu", metadata.etag, chunk->id);
	fbr_ASSERT(metadata.size == chunk->length, "%lu != %lu", metadata.size, chunk->length);
	fbr_ASSERT(!metadata.gzipped, "metadata.gzipped exists");

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, bytes);

	_dstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
}

void
fbr_dstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->id);

	char chunk_path[PATH_MAX];
	_dstore_chunk_path(file, chunk->id, chunk->offset, 0, chunk_path, sizeof(chunk_path));

	fbr_test_logs("DSTORE DELETE chunk: '%s'", chunk_path);

	_dstore_LOCK();

	int ret = unlink(chunk_path);
	fbr_test_ERROR(ret, "unlink() failed %d %d %s", ret, errno, strerror(errno));

	_dstore_chunk_path(file, chunk->id, chunk->offset, 1, chunk_path, sizeof(chunk_path));

	ret = unlink(chunk_path);
	assert_zero(ret);

	fbr_fs_stat_sub(&fs->stats.store_chunks);

	_dstore_UNLOCK();
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
	fbr_directory_name(directory, &dirpath);

	char version[FBR_ID_STRING_MAX];
	fbr_id_string(directory->version, version, sizeof(version));

	char *sub_path = _DSTORE_DATA_PATH;
	if (metadata) {
		sub_path = _DSTORE_META_PATH;
	}

	char *root_sep = "";
	if (dirpath.len) {
		root_sep = "/";
	}

	size_t ret = snprintf(buffer, buffer_len, "%s/%s/%s%s.fiberfsindex.%s",
		_DSTORE->root,
		sub_path,
		dirpath.name,
		root_sep,
		version);
	assert(ret < buffer_len);
}

void
fbr_dstore_index_write(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	fbr_writer_ok(writer);
	assert_dev(writer->output);
	assert_zero_dev(writer->error);

	char index_path[PATH_MAX];
	_dstore_index_path(directory, 0, index_path, sizeof(index_path));

	fbr_test_logs("DSTORE write index: '%s' %s", index_path, writer->is_gzip ? "GZIP" : "");

	_dstore_mkdirs(index_path);

	int fd = _dstore_open_unique(index_path);

	_dstore_writer(fd, writer);

	assert_zero(close(fd));

	struct _dstore_metadata metadata;
	fbr_ZERO(&metadata);
	metadata.etag = directory->version;
	metadata.size = writer->raw_bytes;
	metadata.gzipped = writer->is_gzip;

	_dstore_index_path(directory, 1, index_path, sizeof(index_path));
	_dstore_metadata_write(index_path, &metadata);

	fbr_fs_stat_add_count(&fs->stats.store_index_bytes, writer->bytes);
}

int
fbr_dstore_index_read(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	char index_path[PATH_MAX];
	_dstore_index_path(directory, 1, index_path, sizeof(index_path));

	struct _dstore_metadata metadata;
	_dstore_metadata_read(index_path, &metadata);

	if (metadata.etag != directory->version) {
		fbr_test_logs("DSTORE read index metadata etag found: %lu, expected: %lu",
			metadata.etag, directory->version);
		return 1;
	}

	_dstore_index_path(directory, 0, index_path, sizeof(index_path));

	fbr_test_logs("DSTORE read index: '%s' %s", index_path, metadata.gzipped ? "GZIP" : "");

	int fd = open(index_path, O_RDONLY);

	if (fd < 0) {
		fbr_test_logs("DSTORE read index open(%s) error %d %d %s", index_path, fd, errno,
			strerror(errno));
		return 1;
	}

	struct fbr_request *request = fbr_request_get();

	struct fbr_reader reader;
	fbr_reader_init(fs, &reader, request, metadata.gzipped);
	struct fbr_buffer *output = reader.output;
	fbr_buffer_ok(output);

	struct fbr_index_parser parser;
	fbr_index_parser_init(fs, &parser, directory);

	struct fjson_context json;
	fjson_context_init(&json);
	json.callback = &fbr_index_parse_json;
	json.callback_priv = &parser;

	struct fbr_gzip gzip;
	if (metadata.gzipped) {
		fbr_gzip_inflate_init(&gzip);
		assert_dev(gzip.status == FBR_GZIP_DONE);
	}

	ssize_t read_bytes = 0;
	size_t bytes_in = 0, bytes_out = 0;

	do {
		if (metadata.gzipped) {
			struct fbr_buffer *gbuffer = reader.buffer;
			fbr_buffer_ok(gbuffer);

			gbuffer->buffer_pos = 0;

			assert(gzip.status <= FBR_GZIP_DONE);
			if (gzip.status == FBR_GZIP_DONE) {
				read_bytes = fbr_sys_read(fd, gbuffer->buffer,
					gbuffer->buffer_len);

				bytes_in += read_bytes;
			}

			if (read_bytes < 0) {
				break;
			}

			unsigned char *input = (unsigned char *)gbuffer->buffer;
			unsigned char *output_buf = (unsigned char *)output->buffer +
				output->buffer_pos;
			size_t input_len = read_bytes;
			size_t output_len = output->buffer_len - output->buffer_pos;
			size_t written;

			if (gzip.status == FBR_GZIP_MORE_BUFFER || !read_bytes) {
				input = NULL;
				input_len = 0;
			}

			fbr_gzip_flate(&gzip, input, input_len, output_buf, output_len,
				&written, 0);

			if (gzip.status == FBR_GZIP_ERROR) {
				break;
			}

			output->buffer_pos += written;
			bytes_out += written;
			assert_dev(output->buffer_pos <= output->buffer_len);
		} else {
			assert_zero_dev(reader.buffer);

			unsigned char *output_buf = (unsigned char *)output->buffer +
				output->buffer_pos;
			size_t output_free = output->buffer_len - output->buffer_pos;
			size_t output_len = (random() % 10) + 1;
			assert(output_len <= output_free);

			read_bytes = fbr_sys_read(fd, output_buf, output_len);
			if (read_bytes < 0) {
				break;
			}

			output->buffer_pos += read_bytes;
			assert_dev(output->buffer_pos <= output->buffer_len);

			bytes_in += read_bytes;
			bytes_out += read_bytes;
		}

		fjson_parse_partial(&json, output->buffer, output->buffer_pos);

		output->buffer_pos = fjson_shift(&json, output->buffer, output->buffer_pos,
			output->buffer_len);
	} while (read_bytes > 0 && !json.error);

	assert_zero(close(fd));

	fjson_parse(&json, output->buffer, output->buffer_pos);
	assert(parser.magic == FBR_INDEX_PARSER_MAGIC);

	int ret = 0;

	if (metadata.gzipped) {
		if (gzip.status != FBR_GZIP_DONE) {
			fbr_test_logs("DSTORE read index gzip error");
			ret = 1;
		}
	}
	if (json.error) {
		fbr_test_logs("DSTORE read index json error");
		ret = 1;
	}

	fjson_context_free(&json);
	fbr_index_parser_free(&parser);
	fbr_reader_free(fs, &reader);

	if (metadata.gzipped) {
		fbr_gzip_free(&gzip);
	}

	fbr_test_logs("DSTORE read index bytes in: %zu out: %zu", bytes_in, bytes_out);

	return ret;
}

void
fbr_dstore_index_delete(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	char index_path[PATH_MAX];
	_dstore_index_path(directory, 0, index_path, sizeof(index_path));

	fbr_test_logs("DSTORE DELETE index: '%s'", index_path);

	_dstore_LOCK();

	int ret = unlink(index_path);
	assert_zero(ret);

	_dstore_index_path(directory, 1, index_path, sizeof(index_path));

	ret = unlink(index_path);
	assert_zero(ret);

	_dstore_UNLOCK();
}

int
fbr_dstore_index_root_write(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_writer *writer, struct fbr_directory *previous)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	fbr_writer_ok(writer);
	assert_dev(writer->output);

	fbr_dstore_index_write(fs, directory, writer);

	fbr_id_t previous_version = 0;
	if (previous) {
		fbr_directory_ok(previous);
		assert(previous->version);
		previous_version = previous->version;
	}

	int ret = fbr_dstore_root_write(fs, directory, previous_version);

	if (ret) {
		fbr_dstore_index_delete(fs, directory);
	} else if (previous) {
		fbr_dstore_index_delete(fs, previous);
	}

	return ret;
}

static void
_dstore_root_path(struct fbr_path_name *dirpath, int metadata, char *buffer, size_t buffer_len)
{
	fbr_dstore_ok();
	assert_dev(dirpath);
	assert_dev(buffer);
	assert_dev(buffer_len);

	char *sub_path = _DSTORE_DATA_PATH;
	if (metadata) {
		sub_path = _DSTORE_META_PATH;
	}

	char *root_sep = "";
	if (dirpath->len) {
		root_sep = "/";
	}

	size_t ret = snprintf(buffer, buffer_len, "%s/%s/%s%s.fiberfsroot",
		_DSTORE->root,
		sub_path,
		dirpath->name,
		root_sep);
	assert(ret < buffer_len);
}

int
fbr_dstore_root_write(struct fbr_fs *fs, struct fbr_directory *directory, fbr_id_t existing)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->version);

	char root_path[PATH_MAX];
	struct _dstore_metadata metadata;
	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	_dstore_root_path(&dirpath, 1, root_path, sizeof(root_path));

	_dstore_LOCK();

	_dstore_metadata_read(root_path, &metadata);

	if (metadata.etag != existing) {
		_dstore_UNLOCK();

		fbr_test_logs("DSTORE root mismatch, want %lu, found %lu", existing,
			metadata.etag);

		return EAGAIN;
	} else {
		fbr_test_logs("DSTORE root passed: %lu", existing);
	}

	fbr_ZERO(&metadata);
	metadata.etag = directory->version;

	_dstore_metadata_write(root_path, &metadata);

	_dstore_root_path(&dirpath, 0, root_path, sizeof(root_path));

	char json_buf[128];
	struct fbr_writer json;
	fbr_writer_init_buffer(fs, &json, json_buf, sizeof(json_buf));
	fbr_root_json_gen(fs, &json, directory->version);

	fbr_test_logs("DSTORE write root: %lu previous: %lu", directory->version, existing);

	int fd = open(root_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

	_dstore_writer(fd, &json);

	assert_zero(close(fd));

	_dstore_UNLOCK();

	fbr_fs_stat_add_count(&fs->stats.store_root_bytes, json.bytes);

	fbr_writer_free(fs, &json);

	return 0;
}

fbr_id_t
fbr_dstore_root_read(struct fbr_fs *fs, struct fbr_path_name *dirpath)
{
	fbr_fs_ok(fs);
	assert(dirpath);

	char root_path[PATH_MAX];
	_dstore_root_path(dirpath, 0, root_path, sizeof(root_path));

	_dstore_LOCK();

	int fd = open(root_path, O_RDONLY);

	if (fd < 0) {
		fbr_test_logs("DSTORE root read open() error");
		return 0;
	}

	char json_buf[128];
	ssize_t bytes = fbr_sys_read(fd, json_buf, sizeof(json_buf));
	assert(bytes > 0 && (size_t)bytes <= sizeof(json_buf));

	assert_zero(close(fd));

	struct _dstore_metadata metadata;
	_dstore_root_path(dirpath, 1, root_path, sizeof(root_path));
	_dstore_metadata_read(root_path, &metadata);

	_dstore_UNLOCK();

	fbr_id_t version = fbr_root_json_parse(fs, json_buf, bytes);
	fbr_ASSERT(metadata.etag == version, "%lu != %lu", metadata.etag, version);

	fbr_test_logs("DSTORE read root: %lu", version);

	return version;
}
