/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fbr_core.h"
#include "fuse/fbr_fuse_ops.h"

static size_t
_core_filename_inline_len(size_t name_len)
{
	if (name_len < FBR_FILE_EMBED_LEN) {
		return 0;
	}

	return name_len + 1;
}

void
_core_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
    size_t name_len)
{
	assert(filename);

	if (!_core_filename_inline_len(name_len)) {
		assert_zero(filename_ptr);

		filename->layout = FBR_FILENAME_EMBED;
		filename_ptr = filename->name_data;
	} else {
		assert(filename_ptr);
		assert(name_len);

		filename->layout = FBR_FILENAME_INLINE;
		filename->name_ptr = filename_ptr;

	}

	if (name_len) {
		memcpy(filename_ptr, name, name_len + 1);
	}
}

// TODO take in a req?
struct fbr_file *
fbr_file_alloc(char *name, size_t name_len)
{
	struct fbr_file *file;

	size_t inline_len = _core_filename_inline_len(name_len);

	file = calloc(1, sizeof(*file) + inline_len);
	fbr_fuse_ASSERT(file, NULL);

	file->magic = FBR_FILE_MAGIC;

	char *inline_ptr = NULL;
	if (inline_len) {
		inline_ptr = (char*)file + sizeof(*file);
	}

	_core_filename_init(&file->filename, inline_ptr, name, name_len);

	fbr_file_ok(file);

	return file;
}

struct fbr_directory *
fbr_directory_alloc(void)
{
	struct fbr_directory *directory;

	directory = calloc(1, sizeof(*directory));
	fbr_fuse_ASSERT(directory, NULL);

	directory->magic = FBR_DIRECTORY_MAGIC;
	directory->file.magic = FBR_FILE_MAGIC;

	_core_filename_init(&directory->file.filename, NULL, NULL, 0);

	fbr_directory_ok(directory);

	return directory;
}

const char *
fbr_get_filename(struct fbr_file *file)
{
	fbr_file_ok(file);

	if (file->filename.layout == FBR_FILENAME_EMBED) {
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

void
fbr_directory_free(struct fbr_directory *directory)
{
	fbr_directory_ok(directory);

	struct fbr_file *file, *temp;

	TAILQ_FOREACH_SAFE(file, &directory->file_list, file_entry, temp) {
		fbr_file_ok(file);

		TAILQ_REMOVE(&directory->file_list, file, file_entry);

		fbr_file_free(file);
	}

	assert(TAILQ_EMPTY(&directory->file_list));
	//assert(RB_EMPTY(&test->cmd_tree));

	fbr_ZERO(directory);

	free(directory);
}
