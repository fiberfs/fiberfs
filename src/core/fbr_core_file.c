/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_core_fs.h"
#include "fuse/fbr_fuse_ops.h"

struct fbr_file *
fbr_file_alloc(struct fbr_core_fs *fs, struct fbr_directory *directory, char *name,
    size_t name_len)
{
	fbr_core_fs_ok(fs);
	fbr_directory_ok(directory);
	assert(name);

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	struct fbr_file *file = calloc(1, sizeof(*file) + inline_len);
	fbr_fuse_ASSERT(file, NULL);

	if (inline_len) {
		inline_ptr = (char*)file + sizeof(*file);
	}

	file->magic = FBR_FILE_MAGIC;
	file->inode = fbr_core_fs_gen_inode(fs);

	fbr_filename_init(&file->filename, inline_ptr, name, name_len);

	fbr_file_ok(file);

	fbr_directory_add(directory, file);

	return file;
}

int
fbr_file_cmp(const struct fbr_file *f1, const struct fbr_file *f2)
{
	fbr_file_ok(f1);
	fbr_file_ok(f2);

	return fbr_filename_cmp(&f1->filename, &f2->filename);
}

void
fbr_file_free(struct fbr_file *file)
{
	fbr_file_ok(file);

	fbr_filename_free(&file->filename);

	fbr_ZERO(file);

	free(file);
}
