/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_PATH_H_INCLUDED_
#define _FBR_PATH_H_INCLUDED_

#define FBR_PATH_LAYOUT_LEN			2
#define FBR_PATH_EMBED_LEN_SIZE			(8 - FBR_PATH_LAYOUT_LEN)
#define FBR_PATH_EMBED_LEN_MAX			(1 << FBR_PATH_EMBED_LEN_SIZE)
#define FBR_PATH_EMBED_LEN			(sizeof(struct fbr_path_ptr) - 1)
#define FBR_PATH_PTR_LEN_SIZE			((sizeof(short) * 8) - FBR_PATH_LAYOUT_LEN)
#define FBR_PATH_PTR_LEN_MAX			(1 << FBR_PATH_PTR_LEN_SIZE)

enum fbr_path_layout {
	FBR_PATH_NULL = 0,
	FBR_PATH_EMBED_DIR,
	FBR_PATH_EMBED_FILE,
	FBR_PATH_PTR,
	__FBR_PATH_LAYOUT_END
};

struct _fbr_path_layout {
	unsigned int				value:FBR_PATH_LAYOUT_LEN;
};

struct fbr_path_ptr {
	unsigned int				layout:FBR_PATH_LAYOUT_LEN;
	unsigned int				dir_len:FBR_PATH_PTR_LEN_SIZE;
	unsigned int				file_len:FBR_PATH_PTR_LEN_SIZE;
	// put unused in here?
	union {
		const char			*value;
	};
};

struct fbr_path_embed {
	unsigned int				layout:FBR_PATH_LAYOUT_LEN;
	unsigned int				len:FBR_PATH_EMBED_LEN_SIZE;
	char					data[FBR_PATH_EMBED_LEN];
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

extern const struct fbr_path_name *PATH_NAME_EMPTY;

void *fbr_path_storage_alloc(size_t size, size_t path_offset, const struct fbr_path_name *dirname,
	const struct fbr_path_name *filename);
void fbr_path_init_dir(struct fbr_path *path, const char *dirname, size_t dirname_len);
void fbr_path_init_file(struct fbr_path *path, const char *filename, size_t filename_len);
void fbr_path_get_dir(const struct fbr_path *path, struct fbr_path_name *result_dir);
void fbr_path_get_file(const struct fbr_path *path, struct fbr_path_name *result_file);
void fbr_path_get_full(const struct fbr_path *path, struct fbr_path_name *result);
int fbr_path_cmp_dir(const struct fbr_path *dir1, const struct fbr_path *dir2);
int fbr_path_cmp_file(const struct fbr_path *file1, const struct fbr_path *file2);
void fbr_path_name_init(struct fbr_path_name *name, const char *s);
int fbr_path_name_cmp(struct fbr_path_name *name, const char *s);
void fbr_path_free(struct fbr_path *path);

#endif /* _FBR_PATH_H_INCLUDED_ */
