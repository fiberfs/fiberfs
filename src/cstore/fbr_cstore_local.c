/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <stdio.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_cstore.h"
#include "fbr_cstore_api.h"
#include "fjson.h"
#include "core/fs/fbr_fs.h"
#include "utils/fbr_sys.h"

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

	const char *subpath = FBR_CSTORE_DATA_DIR;
	if (metadata) {
		subpath = FBR_CSTORE_META_DIR;
	}

	int ret = snprintf(output, output_len, "%s/%s/%.2s/%.2s/%s",
		cstore->root,
		subpath,
		hash_str,
		hash_str + 2,
		hash_str + 4);
	assert(ret > 0 && (size_t)ret < output_len);
}

int
fbr_cstore_wbuffer_write(struct fbr_fs *fs, struct fbr_file *file, struct fbr_wbuffer *wbuffer)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	fbr_wbuffer_ok(wbuffer);
	assert(wbuffer->state == FBR_WBUFFER_READY);

	struct fbr_cstore *cstore = fbr_cstore_find();
	if (!cstore) {
		return 1;
	}

	fbr_hash_t hash = fbr_chash_wbuffer(fs, file, wbuffer);
	size_t bytes = wbuffer->end;

	char buffer[FBR_PATH_MAX];
	struct fbr_path_name filepath;
	fbr_path_get_full(&file->path, &filepath, buffer, sizeof(buffer));

	unsigned long request_id = FBR_REQID_CSTORE;
	struct fbr_request *request = fbr_request_get();
	if (request) {
		request_id = request->id;
	}

	char path[FBR_PATH_MAX];
	_cstore_gen_path(cstore, hash, 0, path, sizeof(path));

	fbr_log_print(cstore->log, FBR_LOG_CS_WBUFFER, request_id, "%s %zu:%zu %lu %s",
		filepath.name, wbuffer->offset, bytes, wbuffer->id, path);

	struct fbr_cstore_entry *entry = fbr_cstore_insert(cstore, hash, bytes);
	if (!entry) {
		entry = fbr_cstore_get(cstore, hash);
		if (!entry || entry->bytes != bytes) {
			return 1;
		}
	}

	fbr_cstore_set_loading(entry);
	if (entry->state != FBR_CSTORE_LOADING) {
		fbr_cstore_release(cstore, entry);
		return 1;
	}

	int ret = fbr_mkdirs(path);
	if (ret) {
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	if (fbr_sys_exists(path)) {
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	int fd = open(path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	fbr_sys_write(fd, wbuffer->buffer, bytes);
	assert_zero(close(fd));

	struct fbr_cstore_metadata metadata;
	fbr_ZERO(&metadata);
	metadata.etag = wbuffer->id;
	metadata.size = bytes;
	metadata.offset = wbuffer->offset;
	assert(filepath.len < FBR_PATH_MAX);
	memcpy(metadata.path, filepath.name, filepath.len + 1);

	_cstore_gen_path(cstore, hash, 1, path, sizeof(path));
	ret = _cstore_metadata_write(path, &metadata);
	if (ret) {
		fbr_cstore_delete_entry(cstore, entry);

		fbr_cstore_set_error(entry);
		fbr_cstore_remove(cstore, entry);
		return 1;
	}

	//fbr_fs_stat_add_count(&fs->stats.store_bytes, bytes);
	//fbr_fs_stat_add(&fs->stats.store_chunks);
	fbr_fs_stat_add(&cstore->chunks);

	fbr_cstore_set_ok(entry);
	fbr_cstore_release(cstore, entry);

	return 0;
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
