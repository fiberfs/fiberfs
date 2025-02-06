/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fbr_core_files.h"
#include "fuse/fbr_fuse_ops.h"

void
_core_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
    size_t name_len)
{
	assert(filename);

	if (!name_len) {
		assert_zero(filename_ptr);
		assert_zero(name);
		assert_zero(filename->layout);

		 return;
	} else if (!fbr_filename_inline_len(name_len)) {
		assert_zero(filename_ptr);

		filename->layout = FBR_FILENAME_EMBED;
		filename_ptr = filename->name_data;
	} else {
		assert(filename_ptr);

		filename->layout = FBR_FILENAME_INLINE;
		filename->name_ptr = filename_ptr;

	}

	assert(name_len);
	assert(name);
	memcpy(filename_ptr, name, name_len + 1);
}

void
fbr_file_init(struct fbr_file *file, char *inline_ptr, char *name, size_t name_len)
{
	assert(file);

	fbr_ZERO(file);

	file->magic = FBR_FILE_MAGIC;

	_core_filename_init(&file->filename, inline_ptr, name, name_len);

	fbr_file_ok(file);
}

// TODO take in a req?
struct fbr_file *
fbr_file_alloc(char *name, size_t name_len)
{
	struct fbr_file *file;

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	file = malloc(sizeof(*file) + inline_len);
	fbr_fuse_ASSERT(file, NULL);

	if (inline_len) {
		inline_ptr = (char*)file + sizeof(*file);
	}

	fbr_file_init(file, inline_ptr, name, name_len);

	return file;
}

size_t
fbr_filename_inline_len(size_t name_len)
{
	if (name_len < FBR_FILE_EMBED_LEN) {
		return 0;
	}

	return name_len + 1;
}

const char *
fbr_get_filename(struct fbr_file *file)
{
	fbr_file_ok(file);

	if (file->filename.layout == FBR_FILENAME_NONE) {
		return NULL;
	} else if (file->filename.layout == FBR_FILENAME_EMBED) {
		return file->filename.name_data;
	}

	return file->filename.name_ptr;
}

void
fbr_file_free(struct fbr_file *file)
{
	fbr_file_ok(file);

	fbr_ZERO(file);

	free(file);
}
