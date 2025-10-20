/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <pthread.h>
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
    fbr_id_t id, enum fbr_cstore_entry_type type)
{
	fbr_cstore_ok(cstore);
	assert(url);
	assert(url_len);
	assert(id);

	struct fbr_cstore_backend *s3_backend = cstore->s3.backend;
	fbr_hash_t hash;
	if (s3_backend) {
		hash = fbr_cstore_hash_url(s3_backend->host, s3_backend->host_len, url, url_len);
	} else {
		hash = fbr_cstore_hash_url(NULL, 0, url, url_len);
	}

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rlog(FBR_LOG_CSTORE, "DELETE %s %s %lu", path, url, id);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (entry) {
		fbr_cstore_entry_ok(entry);
		fbr_cstore_remove(cstore, entry);

		switch (type) {
			case FBR_CSTORE_FILE_CHUNK:
				fbr_fs_stat_sub(&cstore->stats.wr_chunks);
				break;
			case FBR_CSTORE_FILE_INDEX:
				fbr_fs_stat_sub(&cstore->stats.wr_indexes);
				break;
			default:
				fbr_ABORT("Bad type: %s", fbr_cstore_type_name(type));
		}
	}

	fbr_cstore_s3_send_delete(cstore, url, id);
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
	fbr_cstore_path_chunk(file, wbuffer->id, wbuffer->offset, chunk_path, sizeof(chunk_path));

	fbr_rlog(FBR_LOG_CS_WBUFFER, "WRITE %s %zu %s", chunk_path, wbuf_bytes, path);

	struct chttp_context http;
	chttp_context_init(&http);
	struct fbr_cstore_op_sync sync;
	fbr_cstore_op_sync_init(&sync);
	fbr_cstore_async_wbuffer_send(cstore, &http, chunk_path, wbuffer, &sync);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, wbuf_bytes,
		path, 1);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR loading state");
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}

	size_t bytes = fbr_sys_write(fd, wbuffer->buffer, wbuf_bytes);
	assert_zero(close(fd));

	if (bytes != wbuf_bytes) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
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
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}

	fbr_fs_stat_add_count(&cstore->stats.wr_chunk_bytes, bytes);
	fbr_fs_stat_add(&cstore->stats.wr_chunks);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	fbr_rlog(FBR_LOG_CS_WBUFFER, "WRITE success %zu bytes", bytes);

	fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 0);
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

	fbr_rlog(FBR_LOG_CS_CHUNK, "READ %s %zu:%zu %lu", path, chunk->offset, chunk->length,
		chunk->id);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_ok(cstore, hash);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR ok state");
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	assert_dev(entry->state == FBR_CSTORE_OK);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR open()");
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	struct stat st;
	int ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR size");
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
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR read()");
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
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR metadata");
		fbr_cstore_remove(cstore, entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	fbr_fs_stat_add_count(&cstore->stats.rd_chunk_bytes, chunk->length);

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
	fbr_cstore_release(cstore, entry);
}

static int
_cstore_writer(int fd, struct fbr_writer *writer)
{
	assert_dev(fd >= 0);
	assert_dev(writer);
	assert_dev(writer->bytes);
	assert_dev(writer->output);
	assert_zero(writer->error);

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
	assert(writer->bytes);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);

	char path[FBR_PATH_MAX];
	char index_path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	fbr_cstore_path_index(directory, index_path, sizeof(index_path));

	fbr_rlog(FBR_LOG_CS_INDEX, "WRITE %s %lu %s", index_path, directory->version, path);

	struct chttp_context http;
	chttp_context_init(&http);
	struct fbr_cstore_op_sync sync;
	fbr_cstore_op_sync_init(&sync);
	fbr_cstore_async_index_send(cstore, &http, index_path, writer, directory->version,
		&sync);

	int ret;
	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, writer->bytes,
		path, 1);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR loading state");
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}

	ret = _cstore_writer(fd, writer);
	assert_zero(close(fd));

	if (ret) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR writing");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
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
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	fbr_fs_stat_add_count(&cstore->stats.wr_index_bytes, writer->bytes);
	fbr_fs_stat_add(&cstore->stats.wr_indexes);

	fbr_rlog(FBR_LOG_CS_INDEX, "WRITE success %zu bytes", writer->bytes);

	ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 0);
	return ret;
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

	struct fbr_cstore_metadata metadata;
	struct fbr_cstore_entry *entry;
	int fd;
	int retry = 0;

	while (1) {
		char path[FBR_PATH_MAX];
		fbr_cstore_path_index(directory, path, sizeof(path));

		fbr_rlog(FBR_LOG_CS_INDEX, "READ %s %lu (retry: %d)", path, directory->version,
			retry);

		if (retry == 1) {
			if (!fbr_cstore_backend_enabled(cstore)) {
				return 1;
			}

			int ret = fbr_cstore_s3_get(cstore, hash, path, directory->version, 0,
				FBR_CSTORE_FILE_INDEX);
			if (ret == 400 || ret == 404) {
				return EAGAIN;
			} else if (ret) {
				return 1;
			}
		} else if (retry > 1) {
			return 1;
		}

		retry++;

		entry = fbr_cstore_io_get_ok(cstore, hash);
		if (!entry) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR ok state");

			if (!fbr_cstore_backend_enabled(cstore)) {
				return EAGAIN;
			}

			continue;
		}

		assert_dev(entry->state == FBR_CSTORE_OK);

		fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
		int ret = fbr_cstore_metadata_read(path, &metadata);
		if (ret) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR metadata");
			fbr_cstore_remove(cstore, entry);
			continue;
		}

		assert_dev(metadata.type == FBR_CSTORE_FILE_INDEX);

		if (metadata.etag != directory->version) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR bad version");
			fbr_cstore_remove(cstore, entry);
			continue;
		}

		fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
		fd = open(path, O_RDONLY);
		if (fd < 0) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR open()");
			fbr_cstore_remove(cstore, entry);
			continue;
		}

		break;
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

	int ret = 0;

	if (metadata.gzipped) {
		if (gzip.status != FBR_GZIP_DONE) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR gunzip");
			ret = 1;
		}
	}
	if (json.error) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR json");
		ret = 1;
	}

	fjson_context_free(&json);
	fbr_index_parser_free(&parser);
	fbr_reader_free(fs, &reader);

	if (metadata.gzipped) {
		fbr_gzip_free(&gzip);
	}

	fbr_rlog(FBR_LOG_CS_INDEX, "READ bytes in: %zu out: %zu", bytes_in, bytes_out);

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

	char url[FBR_PATH_MAX];
	size_t url_len = fbr_cstore_s3_index_url(cstore, directory, url, sizeof(url));

	fbr_cstore_io_delete_url(cstore, url, url_len, directory->version, FBR_CSTORE_FILE_INDEX);
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

	fbr_cstore_async_index_remove(fs, directory);

	return 0;
}

int
fbr_cstore_io_root_write(struct fbr_cstore *cstore, struct fbr_writer *root_json,
    const char *root_path, fbr_id_t version, fbr_id_t existing, int enforce)
{
	fbr_cstore_ok(cstore);
	fbr_writer_ok(root_json);
	assert(root_json->bytes);
	assert(root_path);
	assert(version);
	assert(enforce || fbr_cstore_backend_enabled(cstore));

	fbr_hash_t hash = fbr_cstore_hash_path(cstore, root_path, strlen(root_path));

	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rlog(FBR_LOG_CS_ROOT, "WRITE %s %lu %lu %s", root_path, existing, version, path);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		if (existing && enforce) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR bad version want: %lu got: no entry",
				existing);
			fbr_writer_free(root_json);
			return EAGAIN;
		}

		entry = fbr_cstore_io_get_loading(cstore, hash, 100, path, 0);
		if (!entry) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR loading state");
			fbr_writer_free(root_json);
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
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR metadata");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, entry);
			fbr_writer_free(root_json);
			return 1;
		}

		if (metadata.etag != existing && enforce) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR bad version want: %lu got: %lu",
				existing, metadata.etag);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, entry);
			fbr_writer_free(root_json);
			return EAGAIN;
		}
	}

	fbr_rlog(FBR_LOG_CS_ROOT, "WRITE passed %lu (enforce: %d)", existing, enforce);

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag = version;
	metadata.type = FBR_CSTORE_FILE_ROOT;
	fbr_strbcpy(metadata.path, root_path);

	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR write metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_writer_free(root_json);
		return 1;
	}

	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));

	fbr_rlog(FBR_LOG_CS_ROOT, "WRITE root: %s (%lu) prev: %lu (enforce: %d)", path, version,
		existing, enforce);

	if (!fbr_sys_exists(path)) {
		fbr_fs_stat_add(&cstore->stats.wr_roots);
	}

	int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_writer_free(root_json);
		return 1;
	}

	ret = _cstore_writer(fd, root_json);
	assert_zero(close(fd));

	if (ret) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR write root");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		fbr_writer_free(root_json);
		return 1;
	}

	fbr_fs_stat_add_count(&cstore->stats.wr_root_bytes, root_json->bytes);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);
	fbr_writer_free(root_json);

	return 0;
}

fbr_id_t
fbr_cstore_io_root_read(struct fbr_cstore *cstore, const char *root_path, size_t path_len)
{
	fbr_cstore_ok(cstore);
	assert(root_path);
	assert(path_len);

	fbr_rlog(FBR_LOG_CS_ROOT, "READ %s", root_path);

	int skip_ttl = 0;
	if (!fbr_cstore_backend_enabled(cstore) || !cstore->root_ttl_sec) {
		skip_ttl = 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_path(cstore, root_path, path_len);
	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR ok state");
		return 0;
	}

	fbr_cstore_reset_loading(entry);
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	struct fbr_cstore_metadata metadata;
	char path[FBR_PATH_MAX];
	fbr_cstore_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_read(path, &metadata);

	if (ret) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	assert_dev(metadata.type == FBR_CSTORE_FILE_ROOT);

	if (!skip_ttl) {
		double now = fbr_get_time();
		if (metadata.timestamp + cstore->root_ttl_sec < now) {
			fbr_rlog(FBR_LOG_CS_ROOT, "expired");
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, entry);
			return 0;
		}
	}

	fbr_cstore_path(cstore, hash, 0, path, sizeof(path));
	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	char json_buf[FBR_ROOT_JSON_SIZE];
	ssize_t bytes = fbr_sys_read(fd, json_buf, sizeof(json_buf));
	assert_zero(close(fd));

	if (bytes <= 0 || bytes == sizeof(json_buf)) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR read()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

	fbr_cstore_set_ok(entry);

	fbr_id_t version = fbr_root_json_parse(json_buf, bytes);
	if (version != metadata.etag) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR version etag");
		fbr_cstore_remove(cstore, entry);
		return 0;
	}

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

	fbr_rlog(FBR_LOG_CS_ROOT, "DELETE %s %lu", path, directory->version);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR no entry");
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
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR version etag");
		fbr_cstore_release(cstore, entry);
		return 1;
	}

	fbr_cstore_remove(cstore, entry);

	fbr_fs_stat_sub(&cstore->stats.wr_roots);

	// TODO send this to S3...

	return 0;
}
