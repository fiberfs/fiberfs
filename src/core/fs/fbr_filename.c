/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include <limits.h>
#include <stdlib.h>

#include "fiberfs.h"
#include "fbr_fs.h"
#include "core/fuse/fbr_fuse_ops.h"

static size_t
_filename_inline_len(size_t name_len)
{
	struct fbr_filename *filename;

	if (name_len < sizeof(filename->name_data)) {
		return 0;
	}

	return name_len + 1;
}

static void
_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
    size_t name_len)
{
	assert(filename);

	if (!name) {
		assert_zero(filename_ptr);
		assert_zero(name);
		assert_zero(name_len);

		return;
	}
	if (!_filename_inline_len(name_len)) {
		assert_zero(filename_ptr);

		filename->layout = FBR_FILENAME_EMBED;
		filename_ptr = filename->name_data;
	} else {
		assert(filename_ptr);

		filename->layout = FBR_FILENAME_INLINE;
		filename->name_ptr = filename_ptr;

	}

	assert(name);
	assert(name_len <= USHRT_MAX);

	memcpy(filename_ptr, name, name_len);
	filename_ptr[name_len] = '\0';
	filename->len = name_len;
}

void *
fbr_inline_alloc(size_t size, size_t filename_offset, char *name, size_t name_len)
{
	size_t inline_len = _filename_inline_len(name_len);
	char *inline_ptr = NULL;

	void *obj = calloc(1, size + inline_len);
	fbr_fuse_ASSERTF(obj, NULL, "memory failure");

	if (inline_len) {
		inline_ptr = (char*)obj + size;
	}

	struct fbr_filename *filename = (struct fbr_filename*)((char*)obj + filename_offset);

	_filename_init(filename, inline_ptr, name, name_len);

	return obj;
}

const char *
fbr_filename_get(const struct fbr_filename *filename)
{
	assert(filename);
	assert(filename->layout < __FBR_FILENAME_LAYOUT_END);

	if (filename->layout == FBR_FILENAME_NULL) {
		return NULL;
	} else if (filename->layout == FBR_FILENAME_EMBED) {
		return filename->name_data;
	}

	return filename->name_ptr;
}

int
fbr_filename_cmp(const struct fbr_filename *f1, const struct fbr_filename *f2)
{
	assert(f1);
	assert(f2);

	int diff = f1->len - f2->len;

	if (diff) {
		return diff;
	}

	const char *filename1 = fbr_filename_get(f1);
	const char *filename2 = fbr_filename_get(f2);

	assert(filename1);
	assert(filename2);

	return strncmp(filename1, filename2, f1->len);
}

void
fbr_filename_free(struct fbr_filename *filename)
{
	assert(filename);

	if (filename->layout == FBR_FILENAME_ALLOC) {
		free(filename->name_ptr);
	}

	fbr_ZERO(filename);
}
