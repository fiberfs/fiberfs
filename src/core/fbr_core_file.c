/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_core_fs.h"
#include "fuse/fbr_fuse_ops.h"

size_t
fbr_filename_inline_len(size_t name_len)
{
	struct fbr_filename *filename;

	if (name_len < sizeof(filename->name_data)) {
		return 0;
	}

	return name_len + 1;
}

void
fbr_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
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

const char *
fbr_filename_get(const struct fbr_filename *filename)
{
	assert(filename);

	if (filename->layout == FBR_FILENAME_NONE) {
		return NULL;
	} else if (filename->layout == FBR_FILENAME_EMBED) {
		return filename->name_data;
	}

	assert(filename->layout <= FBR_FILENAME_ALLOC);

	return filename->name_ptr;
}

int
fbr_filename_cmp(const struct fbr_file *f1, const struct fbr_file *f2)
{
	fbr_file_ok(f1);
	fbr_file_ok(f2);

	const char *filename1 = fbr_filename_get(&f1->filename);
	const char *filename2 = fbr_filename_get(&f2->filename);

	assert(filename1);
	assert(filename2);

	return strcmp(filename1, filename2);
}

struct fbr_file *
fbr_file_alloc_nolen(char *name)
{
	assert(name);
	return fbr_file_alloc(name, strlen(name));
}

// TODO take in a req?
struct fbr_file *
fbr_file_alloc(char *name, size_t name_len)
{
	struct fbr_file *file;

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	file = calloc(1, sizeof(*file) + inline_len);
	fbr_fuse_ASSERT(file, NULL);

	if (inline_len) {
		inline_ptr = (char*)file + sizeof(*file);
	}

	file->magic = FBR_FILE_MAGIC;

	fbr_filename_init(&file->filename, inline_ptr, name, name_len);

	fbr_file_ok(file);

	return file;
}

void
fbr_file_free(struct fbr_file *file)
{
	fbr_file_ok(file);

	fbr_ZERO(file);

	free(file);
}
