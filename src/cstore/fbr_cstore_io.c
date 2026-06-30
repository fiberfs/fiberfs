/*
 * Copyright (c) 2024-2026 FiberFS LLC
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
fbr_cstore_metadata_write(struct fbr_cstore_hashpath *hashpath,
    struct fbr_cstore_metadata *metadata)
{
	fbr_cstore_hashpath_ok(hashpath);
	assert(metadata);

	int ret = fbr_sys_mkdirs(hashpath->value);
	if (ret) {
		return 1;
	}

	if (!metadata->timestamp) {
		metadata->timestamp = fbr_get_time();
	}

	int fd = open(hashpath->value, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		return 1;
	}

	char buf[256];
	size_t length;

	// p: path
	fbr_sys_write(fd, "{\"p\":\"", 6);
	fbr_sys_write(fd, metadata->path, strlen(metadata->path));

	// e: etag
	if (metadata->etag.length) {
		length = fbr_urlencode(metadata->etag.value, metadata->etag.length, buf,
			sizeof(buf));

		fbr_sys_write(fd, "\",\"e\":\"", 7);
		fbr_sys_write(fd, buf, length);
	}

	// i: timestamp
	length = fbr_bprintf(buf, "%f", metadata->timestamp);

	fbr_sys_write(fd, "\",\"i\":", 6);
	fbr_sys_write(fd, buf, length);

	// s: size
	length = fbr_bprintf(buf, "%lu", metadata->size);

	fbr_sys_write(fd, ",\"s\":", 5);
	fbr_sys_write(fd, buf, length);

	// t: type
	length = fbr_bprintf(buf, "%d", metadata->type);

	fbr_sys_write(fd, ",\"t\":", 5);
	fbr_sys_write(fd, buf, length);

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
			metadata->etag.length = fbr_urldecode(token->svalue, token->svalue_len,
				metadata->etag.value, sizeof(metadata->etag.value));
			assert(metadata->etag.length);
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
fbr_cstore_metadata_read(struct fbr_cstore_hashpath *hashpath,
    struct fbr_cstore_metadata *metadata)
{
	fbr_cstore_hashpath_ok(hashpath);
	assert(metadata);

	fbr_zero(metadata);

	int fd = open(hashpath->value, O_RDONLY);
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
	metadata->error = json.error;

	fjson_context_free(&json);

	return metadata->error;
}

void
fbr_cstore_io_delete_entry(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_entry_ok(entry);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, entry->hash, 0, &hashpath);
	(void)unlink(hashpath.value);

	fbr_cstore_hashpath(cstore, entry->hash, 1, &hashpath);
	(void)unlink(hashpath.value);
}

void
fbr_cstore_io_delete_url(struct fbr_cstore *cstore, const struct fbr_cstore_url *url,
    const char *etag_match, enum fbr_cstore_file_type type)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_url_ok(url);
	assert(type == FBR_CSTORE_FILE_CHUNK || type == FBR_CSTORE_FILE_INDEX);

	int backend = fbr_cstore_backend_enabled(cstore);

	if (cstore->delete_cache || !backend) {
		char url_decoded[FBR_URL_MAX];
		size_t url_decoded_len = fbr_urldecode(url->value, url->length, url_decoded,
			sizeof(url_decoded));

		fbr_hash_t hash;
		if (backend) {
			assert_dev(cstore->s3.backend);
			hash = fbr_cstore_hash_url(cstore->s3.backend->host,
				cstore->s3.backend->host_len, url_decoded, url_decoded_len);
		} else {
			hash = fbr_cstore_hash_url(cstore->s3.host_hash, cstore->s3.host_hash_len,
				url_decoded, url_decoded_len);
		}

		if (etag_match) {
			fbr_rlog(FBR_LOG_CSTORE, "DELETE %s [%s]", url_decoded, etag_match);
		} else {
			fbr_rlog(FBR_LOG_CSTORE, "DELETE %s", url_decoded);
		}

		struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
		if (entry) {
			fbr_cstore_entry_ok(entry);
			fbr_cstore_remove(cstore, &entry);

			switch (type) {
				case FBR_CSTORE_FILE_CHUNK:
					fbr_stat_sub(&cstore->stats.wr_chunks);
					break;
				case FBR_CSTORE_FILE_INDEX:
					fbr_stat_sub(&cstore->stats.wr_indexes);
					break;
				default:
					fbr_ABORT("Bad type: %s", fbr_cstore_type_name(type));
			}
		}
	}

	if (backend) {
		fbr_cstore_s3_send_delete(cstore, url, etag_match, FBR_CSTORE_ROUTE_CLUSTER);
	}
}

static void
_cstore_release(struct fbr_cstore *cstore, struct fbr_cstore_entry *entry, int remove)
{
	assert_dev(cstore);
	assert_dev(entry);

	if (remove) {
		fbr_cstore_remove(cstore, &entry);
	} else {
		fbr_cstore_release(cstore, &entry);
	}

	assert_zero_dev(entry);
}

struct fbr_cstore_entry *
fbr_cstore_io_get_loading(struct fbr_cstore *cstore, fbr_hash_t hash, size_t bytes,
    struct fbr_cstore_hashpath *hashpath)
{
	assert(cstore);

	int backend = fbr_cstore_backend_enabled(cstore);
	int remove_on_error = backend;

	struct fbr_cstore_entry *entry = fbr_cstore_insert(cstore, hash, bytes, 1);
	if (!entry) {
		entry = fbr_cstore_get(cstore, hash);
		if (!entry) {
			return NULL;
		} else if (bytes && entry->bytes != bytes) {
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

	if (!hashpath) {
		return entry;
	}

	fbr_cstore_hashpath_ok(hashpath);

	// TODO skip re-making the root
	int ret = fbr_sys_mkdirs(hashpath->value);
	if (ret) {
		fbr_cstore_set_error(entry);
		_cstore_release(cstore, entry, 1);
		return NULL;
	}

	if (fbr_sys_exists(hashpath->value) && !backend) {
		fbr_cstore_set_error(entry);
		_cstore_release(cstore, entry, 1);
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
		fbr_cstore_release(cstore, &entry);
		assert_zero_dev(entry);
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

	if (!fs->cstore) {
		fbr_cstore_wbuffer_update(fs, wbuffer, FBR_WBUFFER_ERROR);
		return;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, wbuffer->id, wbuffer->offset);
	size_t wbuf_bytes = wbuffer->end;
	assert_dev(wbuf_bytes);

	struct fbr_cstore_hashpath hashpath;
	struct fbr_cstore_path chunk_path;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	fbr_cstore_path_chunk(file, wbuffer->id, wbuffer->offset, &chunk_path);

	fbr_rlog(FBR_LOG_CS_WBUFFER, "WRITE %s %zu %s", chunk_path.value, wbuf_bytes,
		hashpath.value);

	struct chttp_context http;
	chttp_context_init(&http);
	struct fbr_cstore_op_sync sync;
	fbr_cstore_op_sync_init(&sync);
	fbr_cstore_async_wbuffer_send(cstore, &http, &chunk_path, wbuffer, &sync);

	if (fbr_cstore_backend_enabled(cstore) && !cstore->config.force_chunk_write) {
		struct fbr_cstore_backend *backend = fbr_cstore_backend_get(cstore, hash,
			FBR_CSTORE_ROUTE_CLUSTER, 0, 0);

		if (cstore->cluster.size && !fbr_cstore_servers_contains(cstore, backend)) {
			fbr_rlog(FBR_LOG_CS_WBUFFER, "WRITE skipping local");
			fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
			return;
		}
	}

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, wbuf_bytes,
		&hashpath);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR loading state");
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(hashpath.value, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}

	size_t bytes = fbr_sys_write(fd, wbuffer->buffer, wbuf_bytes);
	assert_zero(close(fd));

	if (bytes != wbuf_bytes) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR bytes");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.size = bytes;
	metadata.type = FBR_CSTORE_FILE_CHUNK;
	fbr_strbcpy(metadata.path, chunk_path.value);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	int ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_WBUFFER, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_s3_wbuffer_finish(fs, cstore, &sync, &http, wbuffer, 1);
		return;
	}

	fbr_stat_add_count(&cstore->stats.wr_chunk_bytes, bytes);
	fbr_stat_add(&cstore->stats.wr_chunks);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, &entry);

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

	if (!fs->cstore) {
		fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_EMPTY);
		return;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_hash_t hash = fbr_cstore_hash_chunk(cstore, file, chunk->id, chunk->offset);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rlog(FBR_LOG_CS_CHUNK, "READ %s %zu:%zu", hashpath.value, chunk->offset,
		chunk->length);

	struct fbr_cstore_entry *entry = fbr_cstore_io_get_ok(cstore, hash);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "NO ok state");
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	assert_dev(entry->state == FBR_CSTORE_OK);

	int fd = open(hashpath.value, O_RDONLY);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR open()");
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	struct stat st;
	int ret = fstat(fd, &st);

	if (ret || (size_t)st.st_size != chunk->length) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR size");
		fbr_cstore_remove(cstore, &entry);
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
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	struct fbr_cstore_metadata metadata;
	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	ret = fbr_cstore_metadata_read(&hashpath, &metadata);

	assert_zero_dev(ret);
	assert_dev(metadata.size == chunk->length);
	assert_dev(metadata.type == FBR_CSTORE_FILE_CHUNK);
	assert_zero_dev(metadata.gzipped);

	if (ret || metadata.size != chunk->length || metadata.gzipped) {
		fbr_rlog(FBR_LOG_CS_CHUNK, "ERROR metadata");
		fbr_cstore_remove(cstore, &entry);
		fbr_cstore_s3_chunk_read(fs, cstore, file, chunk);
		return;
	}

	fbr_stat_add_count(&cstore->stats.rd_chunk_bytes, chunk->length);

	fbr_cstore_chunk_update(fs, file, chunk, FBR_CHUNK_READY);
	fbr_cstore_release(cstore, &entry);
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

	if (!fs->cstore) {
		return 1;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);

	struct fbr_cstore_hashpath hashpath;
	struct fbr_cstore_path index_path;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	fbr_cstore_path_index(directory, &index_path);

	fbr_rlog(FBR_LOG_CS_INDEX, "WRITE %s %s", index_path.value, hashpath.value);

	struct chttp_context http;
	chttp_context_init(&http);
	struct fbr_cstore_op_sync sync;
	fbr_cstore_op_sync_init(&sync);
	fbr_cstore_async_index_send(cstore, &http, &index_path, writer, &sync);

	int ret;
	struct fbr_cstore_entry *entry = fbr_cstore_io_get_loading(cstore, hash, writer->bytes,
		&hashpath);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR loading state");
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	int fd = open(hashpath.value, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}

	ret = _cstore_writer(fd, writer);
	assert_zero(close(fd));

	if (ret) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR writing");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.size = writer->bytes;
	metadata.type = FBR_CSTORE_FILE_INDEX;
	metadata.gzipped = writer->is_gzip;
	fbr_strbcpy(metadata.path, index_path.value);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_INDEX, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		ret = fbr_cstore_s3_send_finish(cstore, &sync, &http, 1);
		return ret;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, &entry);
	assert_zero_dev(entry);

	fbr_stat_add_count(&cstore->stats.wr_index_bytes, writer->bytes);
	fbr_stat_add(&cstore->stats.wr_indexes);

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

	if (!fs->cstore) {
		return 1;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	fbr_hash_t hash = fbr_cstore_hash_index(cstore, directory);

	struct fbr_cstore_metadata metadata;
	struct fbr_cstore_entry *entry;
	struct fbr_cstore_entry *entry_ref = NULL;
	int fd;
	int retry = 0;

	while (1) {
		struct fbr_cstore_path path;
		fbr_cstore_path_index(directory, &path);

		fbr_rlog(FBR_LOG_CS_INDEX, "READ %s %lu (retry: %d)", path.value,
			directory->version, retry);

		if (entry_ref) {
			fbr_cstore_release(cstore, &entry_ref);
			assert_zero_dev(entry_ref);
		}

		if (retry == 1 || retry == 2) {
			if (!fbr_cstore_backend_enabled(cstore)) {
				return 1;
			}

			struct fbr_cstore_fetch_context fetch;
			struct chttp_context http;

			chttp_context_init(&http);
			fbr_cstore_fetch_init(&fetch, cstore, &http, FBR_CSTORE_FILE_INDEX,
				&path, NULL, 0, 0, FBR_CSTORE_ROUTE_CLUSTER);

			int ret = fbr_cstore_s3_get_write(&fetch, hash, &entry_ref);
			assert_dev(http.state == CHTTP_STATE_NONE);

			if (ret == 400 || ret == 404) {
				return EAGAIN;
			}
		} else if (retry > 2) {
			return 1;
		}

		retry++;

		entry = fbr_cstore_io_get_ok(cstore, hash);
		if (!entry) {
			fbr_rlog(FBR_LOG_CS_INDEX, "NO ok state");

			if (!fbr_cstore_backend_enabled(cstore)) {
				assert_zero(entry_ref);
				return EAGAIN;
			}

			continue;
		}

		if (entry_ref) {
			fbr_cstore_release(cstore, &entry_ref);
			assert_zero_dev(entry_ref);
		}

		fbr_cstore_entry_ok(entry);
		assert_dev(entry->state == FBR_CSTORE_OK);

		struct fbr_cstore_hashpath hashpath;
		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		int ret = fbr_cstore_metadata_read(&hashpath, &metadata);
		if (ret) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR metadata");
			fbr_cstore_remove(cstore, &entry);
			continue;
		}

		assert_dev(metadata.type == FBR_CSTORE_FILE_INDEX);

		fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
		fd = open(hashpath.value, O_RDONLY);
		if (fd < 0) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR open()");
			fbr_cstore_remove(cstore, &entry);
			continue;
		}

		break;
	}

	assert_zero(entry_ref);

	struct fbr_request *request = fbr_request_get();

	struct fbr_reader reader;
	fbr_reader_init(fs, &reader, request, metadata.gzipped);
	struct fbr_buffer *output = reader.output;
	fbr_buffer_ok(output);

	struct fbr_index_parser parser;
	struct fjson_context json;
	fbr_index_parser_init(fs, &parser, directory, &json);

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
				if (read_bytes < 0) {
					break;
				}

				bytes_in += read_bytes;
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

	int errors = 0;

	if (metadata.gzipped) {
		if (gzip.status != FBR_GZIP_DONE) {
			fbr_rlog(FBR_LOG_CS_INDEX, "ERROR gunzip");
			errors += 1;
		}

		fbr_gzip_free(&gzip);
	}

	errors += fbr_index_parser_validate(&parser);

	fbr_index_parser_free(&parser);
	fbr_reader_free(fs, &reader);

	fbr_rlog(FBR_LOG_CS_INDEX, "READ bytes in: %zu out: %zu", bytes_in, bytes_out);

	fbr_cstore_release(cstore, &entry);

	return errors;
}

void
fbr_cstore_io_index_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);

	if (!fs->cstore) {
		return;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_cstore_url url;
	fbr_cstore_s3_index_url(cstore, directory, &url);

	fbr_cstore_io_delete_url(cstore, &url, NULL, FBR_CSTORE_FILE_INDEX);
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
    struct fbr_cstore_path *root_path, struct fbr_etag *etag, const char *etag_match, int enforce,
    double timestamp, struct fbr_cstore_entry **entry_ref)
{
	fbr_cstore_ok(cstore);
	fbr_writer_ok(root_json);
	assert(root_json->bytes);
	fbr_cstore_path_ok(root_path);
	assert(etag);
	assert(timestamp);

	int backend = fbr_cstore_backend_enabled(cstore);
	if (backend) {
		assert(etag->length);
	} else {
		assert_zero(etag->length);
		assert(enforce);
	}

	fbr_hash_t hash = fbr_cstore_hash_path(cstore, root_path->value, root_path->length);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rlog(FBR_LOG_CS_ROOT, "WRITE %s [%s] [%s enforce: %d] %s", root_path->value,
		backend ? etag->value : "0",
		etag_match ? etag_match : "0", enforce, hashpath.value);

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		if (etag_match && enforce) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR bad version want: [%s] got: no entry",
				etag_match);
			fbr_writer_free(root_json);
			return EAGAIN;
		}

		entry = fbr_cstore_io_get_loading(cstore, hash, FBR_CSTORE_ROOT_SIZE, &hashpath);
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
		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		int ret = fbr_cstore_metadata_read(&hashpath, &metadata);
		if (ret) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR metadata");
			fbr_cstore_set_error(entry);
			fbr_cstore_remove(cstore, &entry);
			fbr_writer_free(root_json);
			return 1;
		}

		if (enforce && (!etag_match || strcmp(etag_match, metadata.etag.value))) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR bad etag want: [%s] got: [%s]",
				etag_match, metadata.etag.value);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, &entry);
			fbr_writer_free(root_json);
			return EAGAIN;
		} else if (!enforce && timestamp <= metadata.timestamp) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR newer write found: %lf current: %lf",
				metadata.timestamp, timestamp);
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, &entry);
			fbr_writer_free(root_json);
			return 1;
		}
	}

	if (enforce) {
		fbr_rlog(FBR_LOG_CS_ROOT, "WRITE ETag passed [%s]", etag_match ? etag_match : "0");
	}

	if (!backend) {
		fbr_cstore_gen_etag(etag);
		fbr_rlog(FBR_LOG_CS_ROOT, "WRITE new ETag [%s]", etag->value);
	}

	struct fbr_cstore_metadata metadata;
	fbr_zero(&metadata);
	metadata.etag.length = fbr_strbcpy(metadata.etag.value, etag->value);
	metadata.size = root_json->bytes;
	metadata.timestamp = timestamp;
	metadata.type = FBR_CSTORE_FILE_ROOT;
	fbr_strbcpy(metadata.path, root_path->value);

	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	int ret = fbr_cstore_metadata_write(&hashpath, &metadata);
	if (ret) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR write metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_writer_free(root_json);
		return 1;
	}

	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	if (!fbr_sys_exists(hashpath.value)) {
		fbr_stat_add(&cstore->stats.wr_roots);
	}

	int fd = open(hashpath.value, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_writer_free(root_json);
		return 1;
	}

	ret = _cstore_writer(fd, root_json);
	assert_zero(close(fd));

	if (ret) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR write root");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		fbr_writer_free(root_json);
		return 1;
	}

	fbr_stat_add_count(&cstore->stats.wr_root_bytes, root_json->bytes);
	fbr_stat_add(&cstore->stats.wr_root_updates);

	if (entry_ref) {
		assert_zero_dev(*entry_ref);

		fbr_cstore_ref(cstore, entry);
		*entry_ref = entry;
	}

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, &entry);
	fbr_writer_free(root_json);

	fbr_rlog(FBR_LOG_CS_ROOT, "WRITE success");

	return 0;
}

fbr_id_t
fbr_cstore_io_root_read(struct fbr_cstore *cstore, struct fbr_cstore_path *root_path,
    struct fbr_etag *etag, unsigned int attempts)
{
	fbr_cstore_ok(cstore);
	fbr_cstore_path_ok(root_path);
	assert(etag);

	fbr_rlog(FBR_LOG_CS_ROOT, "READ %s", root_path->value);

	int skip_ttl = 0;
	if (!fbr_cstore_backend_enabled(cstore) || attempts) {
		skip_ttl = 1;
	}

	fbr_hash_t hash = fbr_cstore_hash_path(cstore, root_path->value, root_path->length);
	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (!entry) {
		fbr_rlog(FBR_LOG_CS_ROOT, "NO ok state");
		return 0;
	}

	fbr_cstore_reset_loading(entry);
	fbr_cstore_entry_ok(entry);
	assert_dev(entry->state == FBR_CSTORE_LOADING);

	struct fbr_cstore_hashpath hashpath;
	struct fbr_cstore_metadata metadata;
	fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
	int ret = fbr_cstore_metadata_read(&hashpath, &metadata);

	if (ret) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR metadata");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		return 0;
	}

	assert_dev(metadata.type == FBR_CSTORE_FILE_ROOT);

	if (!skip_ttl) {
		double now = fbr_get_time();
		double root_time = metadata.timestamp +
			(cstore->config.root_ttl_sec ? cstore->config.root_ttl_sec :
				FBR_CSTORE_ROOT_TTL_MIN);

		if (root_time < now) {
			fbr_rlog(FBR_LOG_CS_ROOT, "expired");
			fbr_cstore_set_ok(entry);
			fbr_cstore_release(cstore, &entry);
			return 0;
		}
	}

	etag->length = fbr_strbcpy(etag->value, metadata.etag.value);
	assert(etag->length);

	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);
	int fd = open(hashpath.value, O_RDONLY);
	if (fd < 0) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR open()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		return 0;
	}

	char json_buf[FBR_ROOT_JSON_SIZE];
	ssize_t bytes = fbr_sys_read(fd, json_buf, sizeof(json_buf));
	assert_zero(close(fd));

	if (bytes <= 0 || bytes == sizeof(json_buf)) {
		fbr_rlog(FBR_LOG_CS_ROOT, "ERROR read()");
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, &entry);
		return 0;
	}

	fbr_cstore_set_ok(entry);

	fbr_id_t version = fbr_root_json_parse(json_buf, bytes);

	fbr_cstore_release(cstore, &entry);

	return version;
}

int
fbr_cstore_io_root_remove(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	fbr_directory_ok(directory);
	assert_dev(directory->version);
	assert_zero_dev(directory->file_count);

	if (!fs->cstore) {
		return 1;
	}

	struct fbr_cstore *cstore = fs->cstore;
	fbr_cstore_ok(cstore);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	fbr_hash_t hash = fbr_cstore_hash_root(cstore, &dirpath);

	struct fbr_cstore_hashpath hashpath;
	fbr_cstore_hashpath(cstore, hash, 0, &hashpath);

	fbr_rlog(FBR_LOG_CS_ROOT, "DELETE ROOT %s [%s] (%s)", hashpath.value, directory->etag.value,
		dirpath.name);

	int backend = fbr_cstore_backend_enabled(cstore);

	if (!backend) {
		struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
		if (!entry) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR no entry");
			return 1;
		}

		fbr_cstore_reset_loading(entry);
		fbr_cstore_entry_ok(entry);
		assert_dev(entry->state == FBR_CSTORE_LOADING);

		struct fbr_cstore_metadata metadata;
		fbr_cstore_hashpath(cstore, hash, 1, &hashpath);
		int ret = fbr_cstore_metadata_read(&hashpath, &metadata);

		fbr_cstore_set_ok(entry);

		if (ret) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR metadata");
			fbr_cstore_remove(cstore, &entry);
			fbr_stat_sub(&cstore->stats.wr_roots);
			return 1;
		} else if (strcmp(metadata.etag.value, directory->etag.value)) {
			fbr_rlog(FBR_LOG_CS_ROOT, "ERROR version etag");
			fbr_cstore_release(cstore, &entry);
			return EAGAIN;
		}

		fbr_cstore_remove(cstore, &entry);
		fbr_stat_sub(&cstore->stats.wr_roots);

		return 0;
	}

	struct fbr_cstore_entry *entry = fbr_cstore_get(cstore, hash);
	if (entry) {
		fbr_cstore_remove(cstore, &entry);
		fbr_stat_sub(&cstore->stats.wr_roots);
	}

	struct fbr_cstore_url url;
	fbr_cstore_s3_root_url(cstore, &dirpath, &url);

	int ret = fbr_cstore_s3_send_delete(cstore, &url, directory->etag.value,
		FBR_CSTORE_ROUTE_CLUSTER);

	return ret;
}
