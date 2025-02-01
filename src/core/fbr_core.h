/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_CORE_H_INCLUDED_
#define _FBR_CORE_H_INCLUDED_

enum FBR_FILENAME_LAYOUT {
	FBR_FILENAME_NONE = 0,
	FBR_FILENAME_EMBED,
	FBR_FILENAME_INLINE,
	FBR_FILENAME_CONST,
	FBR_FILENAME_ALLOC
};

/*
 * A file has a name, inode, generation, refcount and attributes
 * The name is memory optimized
 * The generation is updated on each publish, old generations refcount away
 */
struct fbr_file {
	unsigned int			magic;
#define FBR_FILE_CTX_MAGIC		0x8F97F917
};

/*
 * A directory is a extended type of file
 * It has a refcount, a list of children, and search tree of names
 * It has a refcount for each file it contains
 */
struct fbr_directory {
	struct fbr_file			file;

	unsigned int			magic;
#define FBR_DIRECTORY_CTX_MAGIC		0xADB900B1
};

/*
 * There is a global inode search table
 * Each file lives in a directory and this search table
 */

#endif /* _FBR_CORE_H_INCLUDED_ */
