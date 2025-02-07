/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "core/fbr_core_files.h"
#include "data/queue.h"
#include "data/tree.h"
#include "fuse/fbr_fuse_ops.h"

RB_GENERATE_STATIC(fbr_filename_tree, fbr_file, filename_entry, fbr_filename_cmp)

struct fbr_directory *
fbr_directory_root_alloc(void)
{
	return fbr_directory_alloc(NULL, 0);
}

struct fbr_directory *
fbr_directory_alloc_nolen(char *name)
{
	assert(name);
	return fbr_directory_alloc(name, strlen(name));
}

struct fbr_directory *
fbr_directory_alloc(char *name, size_t name_len)
{
	struct fbr_directory *directory;

	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	directory = calloc(1, sizeof(*directory) + inline_len);
	fbr_fuse_ASSERT(directory, NULL);

	if (inline_len) {
		inline_ptr = (char*)directory + sizeof(*directory);
	}

	directory->magic = FBR_DIRECTORY_MAGIC;

	fbr_filename_init(&directory->dirname, inline_ptr, name, name_len);

	TAILQ_INIT(&directory->file_list);
	RB_INIT(&directory->filename_tree);

	fbr_directory_ok(directory);

	return directory;
}

void
fbr_directory_add(struct fbr_directory *directory, struct fbr_file *file)
{
	fbr_directory_ok(directory);
	fbr_file_ok(file);

	TAILQ_INSERT_TAIL(&directory->file_list, file, file_entry);

	struct fbr_file *ret = RB_INSERT(fbr_filename_tree, &directory->filename_tree, file);
	assert_zero(ret);
}

void
fbr_directory_free(struct fbr_directory *directory)
{
	fbr_directory_ok(directory);

	struct fbr_file *file, *temp;

	TAILQ_FOREACH_SAFE(file, &directory->file_list, file_entry, temp) {
		fbr_file_ok(file);

		TAILQ_REMOVE(&directory->file_list, file, file_entry);

		struct fbr_file *ret = RB_REMOVE(fbr_filename_tree, &directory->filename_tree,
			file);
		assert(file == ret);

		fbr_file_free(file);
	}

	assert(TAILQ_EMPTY(&directory->file_list));
	assert(RB_EMPTY(&directory->filename_tree));

	fbr_ZERO(directory);

	free(directory);
}
