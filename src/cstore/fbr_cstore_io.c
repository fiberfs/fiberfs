/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "fiberfs.h"
#include "chttp.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "fbr_cstore_api.h"
#include "fjson.h"
#include "utils/fbr_sys.h"

int
fbr_cstore_metadata_write(char *path, struct fbr_cstore_metadata *metadata)
{
	assert_dev(path);
	assert_dev(metadata);

	int ret = fbr_sys_mkdirs(path);
	if (ret) {
		return 1;
	}

	metadata->timestamp = fbr_get_time();

	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		return 1;
	}

	// p: path
	fbr_sys_write(fd, "{\"p\":\"", 6);
	fbr_sys_write(fd, metadata->path, strlen(metadata->path));

	// e: etag
	char buf[64];
	fbr_id_string(metadata->etag, buf, sizeof(buf));

	fbr_sys_write(fd, "\",\"e\":\"", 7);
	fbr_sys_write(fd, buf, strlen(buf));

	// i: timestamp
	fbr_bprintf(buf, "%f", metadata->timestamp);

	fbr_sys_write(fd, "\",\"i\":", 6);
	fbr_sys_write(fd, buf, strlen(buf));

	// s: size
	fbr_bprintf(buf, "%lu", metadata->size);

	fbr_sys_write(fd, ",\"s\":", 5);
	fbr_sys_write(fd, buf, strlen(buf));

	// o: offset
	fbr_bprintf(buf, "%zu", metadata->offset);

	fbr_sys_write(fd, ",\"o\":", 5);
	fbr_sys_write(fd, buf, strlen(buf));

	// t: type
	fbr_bprintf(buf, "%d", metadata->type);

	fbr_sys_write(fd, ",\"t\":", 5);
	fbr_sys_write(fd, buf, strlen(buf));

	// g: gzipped
	fbr_sys_write(fd, ",\"g\":", 5);

	if (metadata->gzipped) {
		fbr_sys_write(fd, "1}", 2);
	} else {
		fbr_sys_write(fd, "0}", 2);
	}

	assert_zero(close(fd));

	return 0;
}

static int
_cstore_parse_metadata(struct fjson_context *ctx, void *priv)
{
	fjson_context_ok(ctx);
	assert(priv);

	struct fbr_cstore_metadata *metadata = (struct fbr_cstore_metadata*)priv;

	struct fjson_token *token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	assert_dev(ctx->tokens_pos >= 2);
	size_t depth = ctx->tokens_pos - 2;

	if (depth == 1 && token->type == FJSON_TOKEN_LABEL) {
		if (token->svalue_len != 1) {
			metadata->_context = '\0';
			return 0;
		}
		metadata->_context = token->svalue[0];
		return 0;
	} else if (depth != 2) {
		metadata->_context = '\0';
		return 0;
	}

	assert_dev(depth == 2);

	if (token->type == FJSON_TOKEN_STRING) {
		if (metadata->_context == 'e') {
			metadata->etag = fbr_id_parse(token->svalue, token->svalue_len);
		} else if (metadata->_context == 'p') {
			assert(token->svalue_len < sizeof(metadata->path));
			memcpy(metadata->path, token->svalue, token->svalue_len);
		}
	} else if (token->type == FJSON_TOKEN_NUMBER) {
		if (metadata->_context == 'i') {
			metadata->timestamp = token->dvalue;
		} else if (metadata->_context == 's') {
			if (token->dvalue >= 0) {
				metadata->size = (size_t)token->dvalue;
			}
		} else if (metadata->_context == 'o') {
			if (token->dvalue >= 0) {
				metadata->offset = (size_t)token->dvalue;
			}
		} else if (metadata->_context == 't') {
			if (token->dvalue >= 0) {
				metadata->type = (int)token->dvalue;
			}
		}else if (metadata->_context == 'g') {
			if (token->dvalue == 0 || token->dvalue == 1) {
				metadata->gzipped = (int)token->dvalue;
			}
		}
	}

	metadata->_context = '\0';

	return 0;
}

int
fbr_cstore_metadata_read(const char *path, struct fbr_cstore_metadata *metadata)
{
	assert(path);
	assert(metadata);

	fbr_zero(metadata);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		metadata->error = 1;
		return 1;
	}

	char buffer[sizeof(*metadata) + 128];
	ssize_t bytes = fbr_sys_read(fd, buffer, sizeof(buffer));
	assert_zero(close(fd));

	if (bytes <= 0 || (size_t)bytes >= sizeof(buffer)) {
		metadata->error = 2;
		return 1;
	}

	struct fjson_context json;
	fjson_context_init(&json);
	json.callback = &_cstore_parse_metadata;
	json.callback_priv = metadata;

	fjson_parse(&json, buffer, bytes);
	int ret = json.error;

	fjson_context_free(&json);

	if (ret) {
		metadata->error = ret;
	}

	return ret;
}

static void
_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry, int remove)
{
	assert_dev(cstore);
	assert_dev(entry);

	if (remove) {
		fbr_cstore_remove(cstore, entry);
	} else {
		fbr_cstore_release(cstore, entry);
	}
}

struct fbr_cstore_entry *
fbr_cstore_io_get_loading(struct fbr_cstore *cstore, fbr_hash_t hash, size_t bytes,
    const char *path, int remove_on_error)
{
	assert_dev(cstore);
	assert_dev(bytes);

	struct fbr_cstore_entry *entry = fbr_cstore_insert(cstore, hash, bytes, 1);
	if (!entry) {
		entry = fbr_cstore_get(cstore, hash);
		if (!entry) {
			return NULL;
		} else if (entry->bytes != bytes) {
			_cstore_release(cstore, entry, remove_on_error);
			return NULL;
		}

		int loading = fbr_cstore_set_loading(entry);
		if (!loading) {
			_cstore_release(cstore, entry, remove_on_error);
			return NULL;
		}
	}

	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_LOADING);

	if (!path) {
		return entry;
	}

	// TODO skip re-making the root
	int ret = fbr_sys_mkdirs(path);
	if (ret) {
		fbr_cstore_set_error(entry);
		_cstore_release(cstore, entry, remove_on_error);
		return NULL;
	}

	if (fbr_sys_exists(path)) {
		fbr_cstore_set_error(entry);
		_cstore_release(cstore, entry, remove_on_error);
		return NULL;
	}

	return entry;
}

struct fbr_cstore_entry *
fbr_cstore_io_get_ok(struct fbr_cstore *cstore, fbr_hash_t hash)
{
	assert_dev(cstore);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		return NULL;
	}

	fbr_cstore_entry_ok(entry);

	enum fbr_cstore_state state = fbr_cstore_wait_loading(entry);
	if (state == FBR_CSTORE_NONE) {
		fbr_cstore_release(cstore, entry);
		return NULL;
	}

	assert(state == FBR_CSTORE_OK);

	return entry;
}

void
fbr_cstore_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer,
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
fbr_cstore_io_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY || wbuffer->state == FBR_WBUFFER_SYNC);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, wbuffer->id, wbuffer->offset);
	size_t wbuf_bytes = wbuffer->end;
	assert_dev(wbuf_bytes);

	char path[FBR_PATH_MAX];
	char chunk_path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	fbr_cstore_path_chunk(NULL, file, wbuffer->id, wbuffer->offset, 0, chunk_path,
		sizeof(chunk_path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "%s %zu %s",
		chunk_path, wbuf_bytes, path);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, wbuf_bytes, path, 1);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR loading state");
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	struct chttp_context s3_request;
	chttp_context_init(&s3_request);
	fbr_cstore_s3_wbuffer_send(cstore, &s3_request, chunk_path, wbuffer);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &s3_request, chunk_path, wbuffer, 1);
		return;
	}

	size_t bytes = fbr_sys_write(fd, wbuffer->buffer, wbuf_bytes);
	assert_zero(close(fd));

	if (bytes != wbuf_bytes) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &s3_request, chunk_path, wbuffer, 1);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = wbuffer->id;
	metadata.size = bytes;
	metadata.offset = wbuffer->offset;
	metadata.type = FBR_CSTORE_FILE_CHUNK;
	fbr_strbcpy(metadata.path, chunk_path);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &s3_request, chunk_path, wbuffer, 1);
		return;
	}

	fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);
	fbr_fs_stat_add(&fs->stats.store_chunks);
	fbr_fs_stat_add(&cstore->stats.wr_chunks);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	fbr_cstore_s3_wbuffer_finish(fs, cstore, &s3_request, chunk_path, wbuffer, 0);
}

void
fbr_cstore_io_delete_entry(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_entry_ok(entry);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, entry->hash, 0, path, sizeof(path));
	(void)unlink(path);

	fbr_cstore_path(cstore, entry->hash, 1, path, sizeof(path));
	(void)unlink(path);
}

void
fbr_cstore_io_delete_url(struct fbr_cstore *cstore, const char *url, size_t url_len,
    fbr_id_t id)
{
	fbr_cstore_ok(cstore);
	assert(url);
	assert(url_len);
	assert(id);

	fbr_hash_t hash = fbr_cstore_hash_url(cstore->s3.host, cstore->s3.host_len, url, url_len);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "DELETE %s %s %lu",
		path, url, id);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR no entry");
		return;
	}

	fbr_cstore_entry_ok(entry);
	fbr_cstore_remove(cstore, entry);

	fbr_fs_stat_sub(&cstore->stats.wr_chunks);

	fbr_cstore_s3_delete(cstore, url, id);
}

void
fbr_cstore_chunk_update(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk,
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
fbr_cstore_io_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY || chunk->state == FBR_CHUNK_LOADING);
	assert(chunk->length);
	assert(chunk->id);
	assert_zero(chunk->external);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, chunk->id, chunk->offset);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "READ %s %zu:%zu %lu",
		path, chunk->offset, chunk->length, chunk->id);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_ok(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR ok state");
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	assert_dev(entry->state == FBR_CSTORE_OK);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR open()");
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	struct stat st;
	int ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR size");
		fbr_cstore_remove(cstore, entry);
		assert_zero(close(fd));
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	ssize_t bytes = fbr_sys_read(fd, chunk->data, chunk->length);

	assert_zero(close(fd));

	if ((size_t)bytes != chunk->length) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR read()");
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	ret = fbr_cstore_metadata_read(path, &metadata);

	assert_zero_dev(ret);
	assert_dev(metadata.etag == chunk->id);
	assert_dev(metadata.offset == chunk->offset);
	assert_dev(metadata.size == chunk->length);
	assert_dev(metadata.type == FBR_CSTORE_FILE_CHUNK);
	assert_zero_dev(metadata.gzipped);

	if (ret || metadata.size != chunk->length || metadata.offset != chunk->offset ||
	    metadata.etag != chunk->id || metadata.gzipped) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "ERROR metadata");
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, chunk->length);

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
	fbr_cstore_release(cstore, entry);
}

static int
_cstore_writer(int fd, struct fbr_writer *writer)
{
	assert_dev(fd >= 0);
	assert_dev(writer);

	size_t bytes = 0;

	struct fbr_buffer *output = writer->output;
	while (output) {
		fbr_buffer_ok(output);

		if (output->buffer_pos) {
			size_t written = fbr_sys_write(fd, output->buffer, output->buffer_pos);
			if (written != output->buffer_pos) {
				return 1;
			}

			bytes += written;
		}

		output = output->next;
	}

	assert(bytes == writer->bytes);

	return 0;
}

int
fbr_cstore_io_index_write(struct fbr_fs *fs, struct fbr_directory *directory,
    struct fbr_writer *writer)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	fbr_writer_ok(writer);
	assert_dev(writer->output);
	assert_zero_dev(writer->error);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);

	char path[FBR_PATH_MAX];
	char index_path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	fbr_cstore_path_index(NULL, directory, 0, index_path, sizeof(index_path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "WRITE %s %lu %s",
		index_path, directory->version, path);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, writer->bytes, path, 1);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR loading state");
		return 1;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	int ret = _cstore_writer(fd, writer);
	assert_zero(close(fd));

	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR writing");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = directory->version;
	metadata.size = writer->bytes;
	metadata.type = FBR_CSTORE_FILE_INDEX;
	metadata.gzipped = writer->is_gzip;
	fbr_strbcpy(metadata.path, index_path);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	fbr_fs_stat_add_count(&fs->stats.store_index_bytes, writer->bytes);
	fbr_fs_stat_add(&cstore->stats.wr_indexes);

	return 0;
}

int
fbr_cstore_io_index_read(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(directory->state == FBR_DIRSTATE_LOADING);
	assert(directory->version);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "READ %s %lu",
		path, directory->version);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_ok(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR ok state");
		return EAGAIN;
	}

	assert_dev(entry->state == FBR_CSTORE_OK);

	struct fbr_cstore_metadata metadata;
	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_read(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR metadata");
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	assert_dev(metadata.type == FBR_CSTORE_FILE_INDEX);

	if (metadata.etag != directory->version) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR bad version");
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR open()");
		fbr_cstore_remove(cstore, entry);
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

			read_bytes = fbr_sys_read(fd, output_buf, output_free);
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

	ret = 0;

	if (metadata.gzipped) {
		if (gzip.status != FBR_GZIP_DONE) {
			fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR gunzip");
			ret = 1;
		}
	}
	if (json.error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR json");
		ret = 1;
	}

	fjson_context_free(&json);
	fbr_index_parser_free(&parser);
	fbr_reader_free(fs, &reader);

	if (metadata.gzipped) {
		fbr_gzip_free(&gzip);
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "READ bytes in: %zu out: %zu",
		bytes_in, bytes_out);

	fbr_cstore_release(cstore, entry);

	return ret;
}

void
fbr_cstore_io_index_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return;
	}

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "DELETE %s %lu",
		path, directory->version);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "ERROR no entry");
		return;
	}

	fbr_cstore_entry_ok(entry);
	fbr_cstore_remove(cstore, entry);

	fbr_fs_stat_sub(&cstore->stats.wr_indexes);
}

int
fbr_cstore_io_index_delete(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_zero(directory->file_count);

	int ret = fbr_cstore_io_root_remove(fs, directory);
	if (ret) {
		return ret;
	}

	fbr_cstore_io_index_remove(fs, directory);

	return 0;
}

int
fbr_cstore_io_root_write(struct fbr_fs *fs, struct fbr_directory *directory, fbr_id_t existing)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->version);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	fbr_hash_t hash = fbr_cstore_hash_root(cstore, &dirpath);

	char path[FBR_PATH_MAX];
	char root_path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	fbr_cstore_path_root(NULL, &dirpath, 0, root_path, sizeof(root_path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "WRITE %s %lu %lu %s",
		root_path, existing, directory->version, path);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		if (existing) {
			fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id,
				"ERROR bad version want: %lu got: no entry", existing);
			return EAGAIN;
		}

		entry = fbr_cstore_io_get_loading(cstore, hash, 100, path, 0);
		if (!entry) {
			fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id,
				"ERROR loading state");
			return EAGAIN;
		}
		fbr_cstore_entry_ok(entry);
		assert_dev(entry->state == FBR_CSTORE_LOADING);
	} else {
		fbr_cstore_reset_loading(entry);
		fbr_cstore_entry_ok(entry);
		assert_dev(entry->state == FBR_CSTORE_LOADING);

		struct fbr_cstore_metadata metadata;
		fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
		int ret = fbr_cstore_metadata_read(path, &metadata);
		if (ret) {
			fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR metadata");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, entry);
			return 1;
		}

		if (metadata.etag != existing) {
			fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id,
				"ERROR bad version want: %lu got: %lu", existing, metadata.etag);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, entry);
			return EAGAIN;
		}
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "WRITE passed %lu", existing);

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = directory->version;
	metadata.type = FBR_CSTORE_FILE_ROOT;
	fbr_strbcpy(metadata.path, root_path);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR write metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	char json_buf[128];
	struct fbr_writer json;
	fbr_writer_init_buffer(fs, &json, json_buf, sizeof(json_buf));
	fbr_root_json_gen(fs, &json, directory->version);

	fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "WRITE root: %s (%lu) prev: %lu",
		path, directory->version, existing);

	if (!fbr_sys_exists(path)) {
		fbr_fs_stat_add(&cstore->stats.wr_roots);
	}

	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	ret = _cstore_writer(fd, &json);
	assert_zero(close(fd));

	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR write root");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_fs_stat_add_count(&fs->stats.store_root_bytes, json.bytes);
	fbr_writer_free(fs, &json);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	return 0;
}

fbr_id_t
fbr_cstore_io_root_read(struct fbr_fs *fs, struct fbr_path_name *dirpath)
{
	fbr_fs_ok(fs);
	assert(dirpath);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 0;
	}

	fbr_hash_t hash = fbr_cstore_hash_root(cstore, dirpath);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "READ %s", path);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR ok state");
		return 0;
	}

	fbr_cstore_reset_loading(entry);
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	char json_buf[128];
	ssize_t bytes = fbr_sys_read(fd, json_buf, sizeof(json_buf));
	assert_zero(close(fd));

	if (bytes <= 0 || bytes == sizeof(json_buf)) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR read()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	struct fbr_cstore_metadata metadata;
	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_read(path, &metadata);

	fbr_cstore_set_ok(entry);

	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR metadata");
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	assert_dev(metadata.type == FBR_CSTORE_FILE_ROOT);

	fbr_id_t version = fbr_root_json_parse(fs, json_buf, bytes);
	if (version != metadata.etag) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR version etag");
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "READ %s version=%ld",
		dirpath->length ? dirpath->name : "(root)", version);

	fbr_cstore_release(cstore, entry);

	return version;
}

int
fbr_cstore_io_root_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->version);
	assert_zero_dev(directory->file_count);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	fbr_hash_t hash = fbr_cstore_hash_root(cstore, &dirpath);

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = fbr_cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "DELETE %s %lu",
		path, directory->version);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR no entry");
		return 1;
	}

	fbr_cstore_reset_loading(entry);
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	struct fbr_cstore_metadata metadata;
	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_read(path, &metadata);

	fbr_cstore_set_ok(entry);

	if (!ret && metadata.etag != directory->version) {
		fbr_log_print(cstore->log, FBR_LOG_CS_ROOT, request_id, "ERROR version etag");
		fbr_cstore_release(cstore, entry);
		return 1;
	}

	fbr_cstore_remove(cstore, entry);

	fbr_fs_stat_sub(&cstore->stats.wr_roots);

	return 0;
}
