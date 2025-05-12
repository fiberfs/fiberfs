/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_STORE_H_INCLUDED_
#define _FBR_STORE_H_INCLUDED_

#include "compress/chttp_gzip.h"
#include "core/fs/fbr_fs.h"

#define FBR_JSON_HEADER				"fiberfs"
#define FBR_JSON_VERSION			1
#define FBR_DEFAULT_BUFFERS			4
#define FBR_DEFAULT_BUFLEN			4096

struct fbr_buffer {
	unsigned int				magic;
#define FBR_BUFFER_MAGIC			0xDB60ECD5

	unsigned int				buffer_free:1;
	unsigned int				do_free:1;

	char					*buffer;
	size_t					buffer_pos;
	size_t					buffer_len;

	struct fbr_buffer			*next;
};

struct fbr_writer {
	unsigned int				magic;
#define FBR_WRITER_MAGIC			0xDE0ACCD3

	struct fbr_buffer			*buffer;
	struct fbr_buffer			*output;

	struct fbr_buffer			buffer_slab[FBR_DEFAULT_BUFFERS];

	struct fbr_workspace			*workspace;
	struct chttp_gzip			gzip;

	size_t					raw_bytes;
	size_t					bytes;

	unsigned int				want_gzip:1;
	unsigned int				is_gzip:1;
	unsigned int				error:1;
};

struct fbr_reader {
	unsigned int				magic;
#define FBR_READER_MAGIC			0x33939170

	struct fbr_buffer			*buffer;
	struct fbr_buffer			*output;
	struct fbr_buffer			_buffer;
	struct fbr_buffer			_output;

	size_t					raw_bytes;
	size_t					bytes;

	unsigned int				was_gzip:1;
};

enum fbr_index_location {
	FBR_INDEX_LOC_NONE = 0,
	FBR_INDEX_LOC_DIRECTORY,
	FBR_INDEX_LOC_FILE,
	FBR_INDEX_LOC_BODY,
	__FBR_INDEX_LOC_SIZE
};

struct fbr_index_parser {
	unsigned int			magic;
#define FBR_INDEX_PARSER_MAGIC		0xE8AC86B7

	char				context[__FBR_INDEX_LOC_SIZE];
	enum fbr_index_location		location;

	struct fbr_fs			*fs;
	struct fbr_directory		*directory;
	struct fbr_file			*file;

	struct {
		fbr_id_t		id;
		size_t			offset;
		size_t			length;
	} chunk;
};

struct fbr_store_callbacks {
	void (*chunk_read_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_chunk *chunk);
	void (*wbuffer_write_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffer);
	int (*wbuffers_flush_f)(struct fbr_fs *fs, struct fbr_file *file,
		struct fbr_wbuffer *wbuffers);
	int (*index_write_f)(struct fbr_fs *fs, struct fbr_directory *directory,
		struct fbr_writer *writer, struct fbr_directory *previous);
	int (*index_read_f)(struct fbr_fs *fs, struct fbr_directory *directory);
	fbr_id_t (*root_read_f)(struct fbr_fs *fs, struct fbr_path_name *dirpath);
};

struct fjson_context;

int fbr_index_write(struct fbr_fs *fs, struct fbr_directory *directory,
	struct fbr_directory *previous);
void fbr_root_json_gen(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t version);
fbr_id_t fbr_root_json_parse(struct fbr_fs *fs, const char *json_buf, size_t json_buf_len);
void fbr_index_read(struct fbr_fs *fs, struct fbr_directory *directory);
void fbr_index_parser_init(struct fbr_fs *fs, struct fbr_index_parser *parser,
	struct fbr_directory *directory);
void fbr_index_parser_free(struct fbr_index_parser *parser);
int fbr_index_parse_json(struct fjson_context *ctx, void *priv);

void fbr_buffer_init(struct fbr_fs *fs, struct fbr_buffer *fbuf, char *buffer,
	size_t buffer_len);
void fbr_buffer_append(struct fbr_buffer *output, const char *buffer, size_t buffer_len);
void fbr_buffers_free(struct fbr_buffer *buffer);
void fbr_buffer_debug(struct fbr_fs *fs, struct fbr_buffer *fbuf, const char *name);

void fbr_writer_init(struct fbr_fs *fs, struct fbr_writer *writer,
	struct fbr_request *request, int want_gzip);
void fbr_writer_init_buffer(struct fbr_fs *fs, struct fbr_writer *writer, char *buffer,
	size_t buffer_len);
void fbr_writer_flush(struct fbr_fs *fs, struct fbr_writer *writer);
void fbr_writer_add(struct fbr_fs *fs, struct fbr_writer *writer, const char *buffer,
	size_t buffer_len);
void fbr_writer_add_ulong(struct fbr_fs *fs, struct fbr_writer *writer, unsigned long value);
void fbr_writer_add_id(struct fbr_fs *fs, struct fbr_writer *writer, fbr_id_t id);
void fbr_writer_free(struct fbr_fs *fs, struct fbr_writer *writer);
void fbr_writer_debug(struct fbr_fs *fs, struct fbr_writer *writer);

void fbr_reader_init(struct fbr_fs *fs, struct fbr_reader *reader,
	struct fbr_request *request, int is_gzip);
void fbr_reader_free(struct fbr_fs *fs, struct fbr_reader *reader);

#define fbr_buffer_ok(buffer)		fbr_magic_check(buffer, FBR_BUFFER_MAGIC)
#define fbr_writer_ok(writer)		fbr_magic_check(writer, FBR_WRITER_MAGIC)
#define fbr_reader_ok(writer)		fbr_magic_check(writer, FBR_READER_MAGIC)
#define fbr_index_parser_ok(parser)	fbr_magic_check(parser, FBR_INDEX_PARSER_MAGIC)

#endif /* _FBR_STORE_H_INCLUDED_ */
