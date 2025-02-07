/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_CORE_H_INCLUDED_
#define _FBR_CORE_H_INCLUDED_

#include <stddef.h>

#include "data/queue.h"
#include "data/tree.h"

#define FBR_FILE_EMBED_LEN			16

enum FBR_FILENAME_LAYOUT {
	FBR_FILENAME_NONE = 0,
	FBR_FILENAME_EMBED,
	FBR_FILENAME_INLINE,
	FBR_FILENAME_CONST,
	FBR_FILENAME_ALLOC
};

struct fbr_filename {
	unsigned char				layout;
	union {
		char				name_data[FBR_FILE_EMBED_LEN];
		char				*name_ptr;
	};
};

struct fbr_file {
	unsigned int				magic;
#define FBR_FILE_MAGIC				0x8F97F917

	struct fbr_filename			filename;

	unsigned long				inode;
	unsigned long				version;

	unsigned int				refcount;

	unsigned int				type;
	unsigned long				size;
	unsigned int				uid;
	unsigned int				gid;

	struct fbr_directory			*directory;

	TAILQ_ENTRY(fbr_file)			file_entry;
	RB_ENTRY(fbr_file)			filename_entry;
};

RB_HEAD(fbr_filename_tree, fbr_file);

struct fbr_directory {
	unsigned int				magic;
#define FBR_DIRECTORY_MAGIC			0xADB900B1

	struct fbr_filename			dirname;

	// TODO directory state

	unsigned long				version;
	unsigned int				refcount;

	TAILQ_HEAD(, fbr_file)			file_list;
	struct fbr_filename_tree		filename_tree;
};

/*
 * Global inode search table: itable
 * Gloabl directory search table: dindex. Contains full paths
 * When a directory has no more references, it and all its children are freed
 */

size_t fbr_filename_inline_len(size_t name_len);
void fbr_filename_init(struct fbr_filename *filename, char *filename_ptr, char *name,
	size_t name_len);
const char *fbr_filename_get(const struct fbr_filename *filename);
int fbr_filename_cmp(const struct fbr_file *f1, const struct fbr_file *f2);

struct fbr_file *fbr_file_alloc_nolen(char *name);
struct fbr_file *fbr_file_alloc(char *name, size_t name_len);
void fbr_file_free(struct fbr_file *file);

struct fbr_directory *fbr_directory_root_alloc(void);
struct fbr_directory *fbr_directory_alloc_nolen(char *name);
struct fbr_directory *fbr_directory_alloc(char *name, size_t name_len);
void fbr_directory_add(struct fbr_directory *directory, struct fbr_file *file);
void fbr_directory_free(struct fbr_directory *directory);

#define fbr_file_ok(file)					\
{								\
	assert(file);						\
	assert((file)->magic == FBR_FILE_MAGIC);		\
}
#define fbr_directory_ok(dir)					\
{								\
	assert(dir);						\
	assert((dir)->magic == FBR_DIRECTORY_MAGIC);		\
}

#endif /* _FBR_CORE_H_INCLUDED_ */
