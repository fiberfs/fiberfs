/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_core_fs.h"
#include "data/queue.h"
#include "data/tree.h"
#include "fuse/fbr_fuse.h"
#include "fuse/fbr_fuse_ops.h"

// TODO this isnt safe to use...
char *FBR_DIRECTORY_ROOT = "_ROOT";

RB_GENERATE_STATIC(fbr_filename_tree, fbr_file, filename_entry, fbr_filename_cmp)

struct fbr_directory *
fbr_directory_root_alloc(void)
{
	struct fbr_directory *root = fbr_directory_alloc_nolen(FBR_DIRECTORY_ROOT);
	fbr_directory_ok(root);

	/* TODO
	assert_zero(root->dirname.layout);

	root->dirname.layout = FBR_FILENAME_CONST;
	root->dirname.name_ptr = FBR_DIRECTORY_ROOT;
	*/

	return root;
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
	size_t inline_len = fbr_filename_inline_len(name_len);
	char *inline_ptr = NULL;

	struct fbr_directory *directory = calloc(1, sizeof(*directory) + inline_len);
	fbr_fuse_ASSERT(directory, NULL);

	if (inline_len) {
		inline_ptr = (char*)directory + sizeof(*directory);
	}

	directory->magic = FBR_DIRECTORY_MAGIC;

	fbr_filename_init(&directory->dirname, inline_ptr, name, name_len);

	TAILQ_INIT(&directory->file_list);
	RB_INIT(&directory->filename_tree);

	fbr_directory_ok(directory);

	// TODO req...
	struct fbr_fuse_context *ctx = fbr_fuse_get_ctx(NULL);
	fbr_dindex_add(ctx->dindex, directory);

	return directory;
}

int
fbr_directory_cmp(const struct fbr_directory *d1, const struct fbr_directory *d2)
{
	fbr_directory_ok(d1);
	fbr_directory_ok(d2);

	const char *dirname1 = fbr_filename_get(&d1->dirname);
	const char *dirname2 = fbr_filename_get(&d2->dirname);

	assert(dirname1);
	assert(dirname2);

	return strcmp(dirname1, dirname2);
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
