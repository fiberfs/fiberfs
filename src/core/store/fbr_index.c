/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fiberfs.h"
#include "fjson.h"
#include "core/fs/fbr_fs.h"
#include "data/tree.h"
#include "fbr_store.h"

struct _root_parser {
	unsigned int			magic;
#define _ROOT_PARSER_MAGIC		0xA7D2947E
	char				context;
	fbr_id_t			root_version;
};

static int
_json_header_peek(const char *json_buf, size_t json_buf_len)
{
	assert_dev(json_buf);

	//           111
	// 0123456789012 (len=13)
	// {"fiberfs":1,

	if (json_buf_len < 13) {
		return -1;
	}

	if (strncmp(json_buf, "{\"fiberfs\":", 11)) {
		return -1;
	}

	errno = 0;

	char *end;
	long version = strtol(&json_buf[11], &end, 10);

	if (errno || version < 0 || version > INT32_MAX) {
		return -1;
	}
	if (*end != ',' && *end != '}') {
		return -1;
	}

	return version;
}

static void
_json_header(struct fbr_fs *fs, struct fbr_writer *json)
{
	assert_dev(fs);
	assert_dev(json);

	// fiberfs: version header
	fbr_writer_add(fs, json,
		"{\"" FBR_JSON_HEADER "\":" FBR_STRINGIFY(FBR_JSON_VERSION) ",",
		2 + (sizeof(FBR_JSON_HEADER) - 1) + 2 +
			(sizeof(FBR_STRINGIFY(FBR_JSON_VERSION)) - 1) + 1);
}

static void
_json_footer(struct fbr_fs *fs, struct fbr_writer *json)
{
	assert_dev(fs);
	assert_dev(json);

	fbr_writer_add(fs, json, "}", 1);
}

static void
_json_body(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_body *body)
{
	assert_dev(fs);
	assert_dev(json);
	assert_dev(body);

	// b: body chunks
	fbr_writer_add(fs, json, ",\"b\":[", 6);

	struct fbr_chunk *chunk = body->chunks;

	while (chunk) {
		fbr_chunk_ok(chunk);
		assert_dev(chunk->state >= FBR_CHUNK_EMPTY);

		// i: chunk id (string)
		fbr_writer_add(fs, json, "{\"i\":\"", 6);
		fbr_writer_add_id(fs, json, chunk->id);

		// o: chunk offset
		fbr_writer_add(fs, json, "\",\"o\":", 6);
		fbr_writer_add_ulong(fs, json, chunk->offset);

		chunk = chunk->next;

		if (chunk) {
			fbr_writer_add(fs, json, "},", 2);
		} else {
			fbr_writer_add(fs, json, "}", 1);
		}
	}

	fbr_writer_add(fs, json, "]", 1);
}

static void
_json_file(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_file *file)
{
	assert_dev(fs);
	assert_dev(json);
	assert_dev(file);

	// n: filename
	fbr_writer_add(fs, json, "{\"n\":\"", 6);

	struct fbr_path_name filename;
	fbr_path_get_file(&file->path, &filename);

	fbr_writer_add(fs, json, filename.name, filename.len);

	// j: file generation
	fbr_writer_add(fs, json, "\",\"j\":", 6);
	fbr_writer_add_ulong(fs, json, file->generation);

	// s: file size
	fbr_writer_add(fs, json, ",\"s\":", 5);
	fbr_writer_add_ulong(fs, json, file->size);

	// m: file mode
	fbr_writer_add(fs, json, ",\"m\":", 5);
	fbr_writer_add_ulong(fs, json, file->mode);

	_json_body(fs, json, &file->body);

	fbr_writer_add(fs, json, "}", 1);
}

static void
_json_directory(struct fbr_fs *fs, struct fbr_writer *json, struct fbr_directory *directory)
{
	assert_dev(fs);
	assert_dev(json);

	// g: generation
	fbr_writer_add(fs, json, "\"g\":", 4);
	fbr_writer_add_ulong(fs, json, directory->generation);

	// f: files array
	fbr_writer_add(fs, json, ",\"f\":[", 6);

	struct fbr_file_ptr *file_ptr;
	int comma = 0;
	RB_FOREACH(file_ptr, fbr_filename_tree, &directory->filename_tree) {
		fbr_file_ptr_ok(file_ptr);
		struct fbr_file *file = file_ptr->file;

		if (comma) {
			fbr_writer_add(fs, json, ",", 1);
		}

		_json_file(fs, json, file);

		comma = 1;
	}

	fbr_writer_add(fs, json, "]", 1);
}

int
fbr_index_write(struct fbr_fs *fs, struct fbr_directory *directory, struct fbr_directory *previous)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_directory_ok(directory);
	assert_dev(directory->version);
	assert_dev(directory->generation);

	struct fbr_request *request = fbr_request_get();

	struct fbr_writer json;
	fbr_writer_init(fs, &json, request, 1);

	_json_header(fs, &json);
	_json_directory(fs, &json, directory);
	_json_footer(fs, &json);

	fbr_writer_flush(fs, &json);

	fbr_writer_debug(fs, &json);

	int ret = EIO;

	if (fs->store->index_write_f) {
		ret = fs->store->index_write_f(fs, directory, &json, previous);
	}

	fbr_writer_free(fs, &json);

	return ret;
}

void
fbr_root_json_gen(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t version)
{
	fbr_fs_ok(fs);
	fbr_writer_ok(writer);
	assert(version);

	_json_header(fs, writer);

	// v: index_version
	fbr_writer_add(fs, writer, "\"v\":\"", 5);
	fbr_writer_add_id(fs, writer, version);
	fbr_writer_add(fs, writer, "\"}", 2);

	fbr_writer_flush(fs, writer);

	fbr_writer_debug(fs, writer);
}

static int
_root_parse(struct fjson_context *ctx, void *priv)
{
	fjson_context_ok(ctx);
	assert(priv);

	struct _root_parser *root_parser = priv;
	fbr_magic_check(root_parser, _ROOT_PARSER_MAGIC);

	struct fjson_token *token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	assert_dev(ctx->tokens_pos >= 2);
	size_t depth = ctx->tokens_pos - 2;

	if (token->type == FJSON_TOKEN_LABEL) {
		if (depth == 1 && token->svalue_len == 1) {
			root_parser->context = token->svalue[0];
			return 0;
		}
	} else if (token->type == FJSON_TOKEN_STRING) {
		if (root_parser->context == 'v' && depth == 2) {
			root_parser->root_version = fbr_id_parse(token->svalue, token->svalue_len);
		}
	}

	root_parser->context = 0;

	return 0;
}

fbr_id_t
fbr_root_json_parse(struct fbr_fs *fs, const char *json_buf, size_t json_buf_len)
{
	fbr_fs_ok(fs);
	assert(json_buf);
	assert(json_buf_len);

	int json_version = _json_header_peek(json_buf, json_buf_len);
	fs->log("INDEX json version: %d", json_version);

	if (json_version < 1 || json_version >= 10) {
		return 0;
	}

	struct _root_parser root_parser = {_ROOT_PARSER_MAGIC, 0, 0};

	struct fjson_context json;
	fjson_context_init(&json);
	json.callback = &_root_parse;
	json.callback_priv = &root_parser;

	fjson_parse(&json, json_buf, json_buf_len);
	assert(root_parser.magic == _ROOT_PARSER_MAGIC);

	if (json.error) {
		root_parser.root_version = 0;
	}

	fjson_context_free(&json);

	return root_parser.root_version;
}

void
fbr_index_read(struct fbr_fs *fs, struct fbr_directory *directory)
{
	fbr_fs_ok(fs);
	assert_dev(fs->store);
	fbr_directory_ok(directory);
	assert_dev(directory->state == FBR_DIRSTATE_LOADING);
	assert_zero_dev(directory->generation);

	struct fbr_path_name dirpath;
	fbr_directory_name(directory, &dirpath);

	fbr_id_t version = 0;

	if (fs->store->root_read_f) {
		version = fs->store->root_read_f(fs, &dirpath);
	}

	if (version == 0) {
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
		return;
	}

	directory->version = version;

	int ret = 1;

	if (fs->store->index_read_f) {
		ret = fs->store->index_read_f(fs, directory);
	}

	if (ret) {
		fbr_directory_set_state(fs, directory, FBR_DIRSTATE_ERROR);
		return;
	}

	assert_dev(directory->generation);

	fbr_directory_set_state(fs, directory, FBR_DIRSTATE_OK);
}

void
fbr_index_parser_init(struct fbr_index_parser *parser, struct fbr_directory *directory)
{
	assert(parser);
	fbr_directory_ok(directory);

	fbr_ZERO(parser);

	parser->magic = FBR_INDEX_PARSER_MAGIC;
	parser->directory = directory;

	fbr_index_parser_ok(parser);
}

void
fbr_index_parser_free(struct fbr_index_parser *parser)
{
	fbr_index_parser_ok(parser);
	fbr_ZERO(parser);
}

static inline int
_parser_match(struct fbr_index_parser *parser, enum fbr_index_location location, char context)
{
	if (parser->location == location && parser->context == context) {
		return 1;
	}

	return 0;
}

int
fbr_index_parse_json(struct fjson_context *ctx, void *priv)
{
	fjson_context_ok(ctx);
	assert(priv);

	struct fbr_index_parser *parser = priv;
	fbr_index_parser_ok(parser);
	assert_dev(parser->directory);

	struct fbr_directory *directory = parser->directory;
	//struct fbr_directory *previous = directory->previous;

	struct fjson_token *token = fjson_get_token(ctx, 0);
	fjson_token_ok(token);

	assert_dev(ctx->tokens_pos >= 2);
	size_t depth = ctx->tokens_pos - 2;

	switch (token->type) {
		case FJSON_TOKEN_OBJECT:
			if (depth == 0 && parser->location == FBR_INDEX_LOC_NONE) {
				parser->location = FBR_INDEX_LOC_DIRECTORY;
			}

			break;
		case FJSON_TOKEN_LABEL:
			if (token->svalue_len == 1) {
				parser->context = token->svalue[0];
			} else {
				parser->context = 0;
			}

			return 0;
		case FJSON_TOKEN_ARRAY:
			if (_parser_match(parser, FBR_INDEX_LOC_DIRECTORY, 'f')) {
				parser->location = FBR_INDEX_LOC_FILE;
			}
			break;
		case FJSON_TOKEN_NUMBER:
			if (_parser_match(parser, FBR_INDEX_LOC_DIRECTORY, 'g')) {
				// TODO parse this as a long
				directory->generation = (unsigned long)token->dvalue;
			}
			break;
		case FJSON_TOKEN_STRING:
			if (_parser_match(parser, FBR_INDEX_LOC_FILE, 'n')) {
				// TODO start here
			}
			break;
		default:
			break;
	}

	parser->context = 0;

	return 0;
}
