/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_PATH_H_INCLUDED_
#define _FBR_PATH_H_INCLUDED_

#include "fiberfs.h"

#define FBR_PATH_LAYOUT_BITS			2
#define FBR_PATH_LAYOUT_MAX			((1 << FBR_PATH_LAYOUT_BITS) - 1)
#define FBR_PATH_EMBED_LEN_BITS			(8 - FBR_PATH_LAYOUT_BITS)
#define FBR_PATH_EMBED_LEN_MAX			((1 << FBR_PATH_EMBED_LEN_BITS) - 1)
#define FBR_PATH_EMBED_BYTES			(sizeof(struct fbr_path_ptr) - 1)
#define FBR_PATH_PTR_LEN_BITS			((sizeof(short) * 8) - FBR_PATH_LAYOUT_BITS)
#define FBR_PATH_PTR_LEN_MAX			((1 << FBR_PATH_PTR_LEN_BITS) - 1)
#define FBR_PATH_PTR2_OFFSET_BITS		(sizeof(short) * 8)
#define FBR_PATH_PTR2_OFFSET_MAX		((1 << FBR_PATH_PTR2_OFFSET_BITS) - 1)

enum fbr_path_layout {
	FBR_PATH_NULL = 0,
	FBR_PATH_EMBED_DIR,
	FBR_PATH_EMBED_FILE,
	FBR_PATH_PTR,
	__FBR_PATH_LAYOUT_END
};

struct _fbr_path_layout {
	unsigned int				value:FBR_PATH_LAYOUT_BITS;
};

struct fbr_path_ptr {
	unsigned int				layout:FBR_PATH_LAYOUT_BITS;
	unsigned int				dir_len:FBR_PATH_PTR_LEN_BITS;
	unsigned int				file_len:FBR_PATH_PTR_LEN_BITS;

	unsigned int				__freebits:2;
	unsigned int				__free;

	const char				*value;
};

struct fbr_path_ptr2 {
	unsigned int				layout:FBR_PATH_LAYOUT_BITS;
	unsigned int				filename_len:FBR_PATH_PTR_LEN_BITS;
	unsigned short				filename_offset;

	unsigned int				__free;

	struct fbr_path_shared			*dirname;
};

struct fbr_path_embed {
	unsigned int				layout:FBR_PATH_LAYOUT_BITS;
	unsigned int				len:FBR_PATH_EMBED_LEN_BITS;

	char					data[FBR_PATH_EMBED_BYTES];
};

struct fbr_path {
	union {
		struct _fbr_path_layout		layout;
		struct fbr_path_embed		embed;
		struct fbr_path_ptr		ptr;
	};
};

struct fbr_path_name {
	size_t					len;
	const char				*name;
};

struct fbr_path_shared {
	unsigned int				magic;
#define FBR_PATH_SHARED_MAGIC			0x9D5FD1C5

	fbr_refcount_t				refcount;

	struct fbr_path_name			value;
};

extern const struct fbr_path_name *PATH_NAME_EMPTY;

void *fbr_path_storage_alloc(size_t size, size_t path_offset, const struct fbr_path_name *dirname,
	const struct fbr_path_name *filename);
void fbr_path_init_dir(struct fbr_path *path, const char *dirname, size_t dirname_len);
void fbr_path_init_file(struct fbr_path *path, const char *filename, size_t filename_len);
void fbr_path_get_dir(const struct fbr_path *path, struct fbr_path_name *result_dir);
const char *fbr_path_get_file(const struct fbr_path *path, struct fbr_path_name *result_file);
const char *fbr_path_get_full(const struct fbr_path *path, struct fbr_path_name *result);
int fbr_path_cmp_dir(const struct fbr_path *dir1, const struct fbr_path *dir2);
int fbr_path_cmp_file(const struct fbr_path *file1, const struct fbr_path *file2);

void fbr_path_name_init(struct fbr_path_name *name, const char *str);
int fbr_path_name_str_cmp(const struct fbr_path_name *name, const char *str);
int fbr_path_name_cmp(const struct fbr_path_name *name1, const struct fbr_path_name *name2);
void fbr_path_name_parent(const struct fbr_path_name *name, struct fbr_path_name *result);
void fbr_path_free(struct fbr_path *path);

void fbr_path_shared_init(struct fbr_path_shared *shared, const struct fbr_path_name *value);
struct fbr_path_shared *fbr_path_shared_alloc(const struct fbr_path_name *value);
void fbr_path_shared_take(struct fbr_path_shared *shared);
int fbr_path_shared_cmp(const struct fbr_path_shared *shared1,
	const struct fbr_path_shared *shared2);
void fbr_path_shared_name(struct fbr_path_shared *shared, struct fbr_path_name *result);
void fbr_path_shared_release(struct fbr_path_shared *shared);

#define fbr_path_shared_ok(shared)					\
{									\
	assert(shared);							\
	assert((shared)->magic == FBR_PATH_SHARED_MAGIC);		\
}

#endif /* _FBR_PATH_H_INCLUDED_ */
