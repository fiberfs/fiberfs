/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/fs/fbr_fs.h"
#include "core/store/fbr_store.h"
#include "fbr_cstore_api.h"
#include "fjson.h"
#include "utils/fbr_sys.h"

static unsigned int
_cstore_request_id(unsigned int default_id)
{
	struct fbr_request *request = fbr_request_get();
	if (request) {
		return request->id;
	}

	return default_id;
}

static int
_cstore_metadata_write(char *path, struct fbr_cstore_metadata *metadata)
{
	assert_dev(path);
	assert_dev(metadata);

	int ret = fbr_mkdirs(path);
	if (ret) {
		return 1;
	}

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);

	// p: path
	fbr_sys_write(fd, "{\"p\":\"", 6);
	fbr_sys_write(fd, metadata->path, strlen(metadata->path));

	// e: etag
	char buf[FBR_ID_STRING_MAX];
	fbr_id_string(metadata->etag, buf, sizeof(buf));

	fbr_sys_write(fd, "\",\"e\":\"", 7);
	fbr_sys_write(fd, buf, strlen(buf));

	// s: size
	ret = snprintf(buf, sizeof(buf), "%lu", metadata->size);
	assert(ret > 0 && (size_t)ret < sizeof(buf));

	fbr_sys_write(fd, "\",\"s\":", 6);
	fbr_sys_write(fd, buf, strlen(buf));

	// o: offset
	ret = snprintf(buf, sizeof(buf), "%lu", metadata->offset);
	assert(ret > 0 && (size_t)ret < sizeof(buf));

	fbr_sys_write(fd, ",\"o\":", 5);
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
		if (metadata->_context == 's') {
			if (token->dvalue >= 0) {
				metadata->size = (size_t)token->dvalue;
			}
		} else if (metadata->_context == 'o') {
			if (token->dvalue >= 0) {
				metadata->offset = (size_t)token->dvalue;
			}
		} else if (metadata->_context == 'g') {
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

	fbr_ZERO(metadata);

	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		return 1;
	}

	char buffer[sizeof(*metadata) + 128];
	ssize_t bytes = fbr_sys_read(fd, buffer, sizeof(buffer));
	assert_zero(close(fd));

	if (bytes <= 0 || (size_t)bytes >= sizeof(buffer)) {
		return 1;
	}

	struct fjson_context json;
	fjson_context_init(&json);
	json.callback = &_cstore_parse_metadata;
	json.callback_priv = metadata;

	fjson_parse(&json, buffer, bytes);
	int ret = json.error;

	fjson_context_free(&json);

	return ret;
}

static void
_cstore_gen_path(struct fbr_cstore *cstore, fbr_hash_t hash, int metadata, char *output,
    size_t output_len)
{
	assert_dev(cstore);
	assert_dev(output);
	assert_dev(output_len);

	char hash_str[FBR_HASH_SLEN];
	fbr_bin2hex(&hash, sizeof(hash), hash_str, sizeof(hash_str));
	assert_dev(strlen(hash_str) > 4);

	const char *sub_path = FBR_CSTORE_DATA_DIR;
	if (metadata) {
		sub_path = FBR_CSTORE_META_DIR;
	}

	int ret = snprintf(output, output_len, "%s/%s/%.2s/%.2s/%s",
		cstore->root,
		sub_path,
		hash_str,
		hash_str + 2,
		hash_str + 4);
	assert(ret > 0 && (size_t)ret < output_len);
}

static struct fbr_cstore_entry *
_cstore_get_loading(struct fbr_cstore *cstore, fbr_hash_t hash, size_t bytes, const char *path)
{
	assert_dev(cstore);
	assert_dev(path);

	struct fbr_cstore_entry *entry = fbr_cstore_insert(cstore, hash, bytes);
	if (!entry) {
		entry = fbr_cstore_get(cstore, hash);
		if (!entry) {
			return NULL;
		} else if (entry->bytes != bytes) {
			fbr_cstore_release(cstore, entry);
			return NULL;
		}
	}

	fbr_cstore_set_loading(entry);
	if (entry->state != FBR_CSTORE_LOADING) {
		fbr_cstore_release(cstore, entry);
		return NULL;
	}

	// TODO skip re-making the root
	int ret = fbr_mkdirs(path);
	if (ret) {
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return NULL;
	}

	if (fbr_sys_exists(path)) {
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return NULL;
	}

	return entry;
}

static void
_cstore_wbuffer_update(struct fbr_fs *fs, struct fbr_wbuffer *wbuffer,
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
fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY || wbuffer->state == FBR_WBUFFER_SYNC);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}

	fbr_hash_t hash = fbr_chash_chunk(fs, file, wbuffer->id, wbuffer->offset);
	size_t wbuf_bytes = wbuffer->end;

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = _cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "%s %zu:%zu %lu %s",
		filepath.name, wbuffer->offset, wbuf_bytes, wbuffer->id, path);

	struct fbr_cstore_entry *entry = _cstore_get_loading(cstore, hash, wbuf_bytes, path);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error loading state");
		_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}

	size_t bytes = fbr_sys_write(fd, wbuffer->buffer, wbuf_bytes);
	assert_zero(close(fd));

	if (bytes != wbuf_bytes) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_ZERO(&metadata);
	metadata.etag = wbuffer->id;
	metadata.size = bytes;
	metadata.offset = wbuffer->offset;
	assert(filepath.len < sizeof(metadata.path));
	memcpy(metadata.path, filepath.name, filepath.len + 1);

	_cstore_gen_path(cstore, hash, 1, path, sizeof(path));
	int ret = _cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}

	fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);
	fbr_fs_stat_add(&fs->stats.store_chunks);
	fbr_fs_stat_add(&cstore->chunks);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_DONE);

	return;
}

void
fbr_cstore_delete_entry(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_entry_ok(entry);

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, entry->hash, 0, path, sizeof(path));
	(void)unlink(path);

	_cstore_gen_path(cstore, entry->hash, 1, path, sizeof(path));
	(void)unlink(path);
}

static void
_cstore_chunk_update(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk,
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
fbr_cstore_chunk_read(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert(chunk->state == FBR_CHUNK_EMPTY || chunk->state == FBR_CHUNK_LOADING);
	assert(chunk->id);
	assert_zero(chunk->external);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	fbr_hash_t hash = fbr_chash_chunk(fs, file, chunk->id, chunk->offset);

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = _cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "%s %zu:%zu %lu %s",
		filepath.name, chunk->offset, chunk->length, chunk->id, path);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error no entry");
		_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	fbr_cstore_entry_ok(entry);
	if (entry->state <= FBR_CSTORE_LOADING) {
		// TODO wait for loading
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error ok state");
		fbr_cstore_release(cstore, entry);
		_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}
	assert(entry->state == FBR_CSTORE_OK);

	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error open()");
		_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_cstore_release(cstore, entry);
		return;
	}

	struct stat st;
	int ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error size");
		_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_cstore_release(cstore, entry);
		assert_zero(close(fd));
		return;
	}

	chunk->do_free = 1;
	chunk->data = malloc(chunk->length);
	assert(chunk->data);

	ssize_t bytes = fbr_sys_read(fd, chunk->data, chunk->length);

	if ((size_t)bytes != chunk->length) {
		fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "error read()");
		_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		fbr_cstore_release(cstore, entry);
		assert_zero(close(fd));
		return;
	}

	assert_zero(close(fd));

	if (fbr_is_dev()) {
		struct fbr_cstore_metadata metadata;
		_cstore_gen_path(cstore, hash, 1, path, sizeof(path));
		ret = fbr_cstore_metadata_read(path, &metadata);
		assert_zero_dev(ret);
		assert_zero_dev(strcmp(metadata.path, filepath.name));
		assert_dev(metadata.etag == chunk->id);
		assert_dev(metadata.offset == chunk->offset);
		assert_dev(metadata.size == chunk->length);
		assert_zero_dev(metadata.gzipped)
	}

	fbr_fs_stat_add_count(&fs->stats.fetch_bytes, chunk->length);

	_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);

	fbr_cstore_release(cstore, entry);
}

// TODO make async version which directly takes path, id, and offset
void
fbr_cstore_chunk_delete(struct fbr_fs *fs, struct fbr_file *file, struct fbr_chunk *chunk)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_chunk_ok(chunk);
	assert_zero(chunk->external);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return;
	}

	fbr_hash_t hash = fbr_chash_chunk(fs, file, chunk->id, chunk->offset);

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = _cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_CHUNK, request_id, "DELETE %s %zu:%zu %lu %s",
		filepath.name, chunk->offset, chunk->length, chunk->id, path);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (entry) {
		fbr_cstore_remove(cstore, entry);
	}

	fbr_fs_stat_sub(&fs->stats.store_chunks);
	fbr_fs_stat_sub(&cstore->chunks);
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
fbr_cstore_index_write(struct fbr_fs *fs, struct fbr_directory *directory,
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

	fbr_hash_t hash = fbr_chash_index(fs, directory);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = _cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "WRITE %s %lu %s",
		dirpath.len ? dirpath.name : "(root)", directory->version, path);

	struct fbr_cstore_entry *entry = _cstore_get_loading(cstore, hash,
		writer->bytes, path);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error loading state");
		return 1;
	}
	fbr_cstore_entry_ok(entry);
	assert(entry->state == FBR_CSTORE_LOADING);

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	int ret = _cstore_writer(fd, writer);
	assert_zero(close(fd));

	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error writing");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	struct fbr_cstore_metadata metadata;
	fbr_ZERO(&metadata);
	metadata.etag = directory->version;
	metadata.size = writer->bytes;

	char version[FBR_ID_STRING_MAX];
	fbr_id_string(directory->version, version, sizeof(version));
	char *root_sep = "";
	if (dirpath.len) {
		root_sep = "/";
	}
	ret = snprintf(metadata.path, sizeof(metadata.path), "%s%s.fiberfsindex.%s",
		dirpath.name, root_sep, version);
	assert(ret > 0 && (size_t)ret < sizeof(metadata.path));

	_cstore_gen_path(cstore, hash, 1, path, sizeof(path));
	ret = _cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	fbr_fs_stat_add_count(&fs->stats.store_index_bytes, writer->bytes);
	fbr_fs_stat_add(&cstore->indexes);

	return 0;
}

int
fbr_cstore_index_read(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	fbr_hash_t hash = fbr_chash_index(fs, directory);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	unsigned long request_id = _cstore_request_id(FBR_REQID_CSTORE);
	fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "READ %s %lu %s",
		dirpath.len ? dirpath.name : "(root)", directory->version, path);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error no entry");
		return 1;
	}

	fbr_cstore_entry_ok(entry);
	if (entry->state <= FBR_CSTORE_LOADING) {
		// TODO wait for loading
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error ok state");
		fbr_cstore_release(cstore, entry);
		return 1;
	}
	assert(entry->state == FBR_CSTORE_OK);

	struct fbr_cstore_metadata metadata;
	_cstore_gen_path(cstore, hash, 1, path, sizeof(path));
	int ret = fbr_cstore_metadata_read(path, &metadata);
	if (ret) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error metadata");
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	if (metadata.etag != directory->version) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error bad version");
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error open()");
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
			fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error gunzip");
			ret = 1;
		}
	}
	if (json.error) {
		fbr_log_print(cstore->log, FBR_LOG_CS_INDEX, request_id, "error json");
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
