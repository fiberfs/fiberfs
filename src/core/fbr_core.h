/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_CORE_H_INCLUDED_
#define _FBR_CORE_H_INCLUDED_

#include "data/queue.h"
#include "data/tree.h"

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
		char				name_data[16];
		char				*name_ptr;
	};
};

struct fbr_file {
	unsigned int				magic;
#define FBR_FILE_CTX_MAGIC			0x8F97F917

	struct fbr_filename			filename;

	unsigned long				inode;
	unsigned long				version;
	unsigned int				refcount;
	unsigned int				type;
	unsigned long				size;
	unsigned int				uid;
	unsigned int				gid;

	TAILQ_ENTRY(fbr_file)			child_entry;
	RB_ENTRY(fbr_file)			filename_entry;
};

RB_HEAD(fbr_filename_tree, fbr_file);

struct fbr_directory {
	struct fbr_file				file;

	unsigned int				magic;
#define FBR_DIRECTORY_CTX_MAGIC			0xADB900B1

	unsigned int				refcount_child;

	TAILQ_HEAD(, fbr_file)			file_list;
	struct fbr_filename_tree		filename_tree;
};

/*
 * There is a global inode search table
 * Each file lives in a directory, this search table, and the kernel
 */

struct fbr_file *fbr_file_alloc(void);

#endif /* _FBR_CORE_H_INCLUDED_ */
