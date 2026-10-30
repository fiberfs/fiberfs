/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_IOCMD_H_INCLUDED_
#define _FBR_IOCMD_H_INCLUDED_

#include <sys/ioctl.h>

#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_path.h"

#define FBR_IOCMD_PING_REQ			_IOWR('P', 1, struct fbr_iocmd_ping)
#define FBR_IOCMD_IMPORT_REQ			_IOW('I', 1, struct fbr_iocmd_import)
#define FBR_IOCMD_MERGE_REQ			_IOW('M', 1, struct fbr_iocmd_merge)

struct fbr_iocmd_ping {
	unsigned int				magic;
#define FBR_IOCMD_PING_MAGIC			0x8D5BB37C

	fbr_bitflag_t				ping:1;
	fbr_bitflag_t				pong:1;

	char					version[64];
};

struct fbr_iocmd_import {
	unsigned int				magic;
#define FBR_IOCMD_IMPORT_MAGIC			0xB9AB7DFD

	fbr_bitflag_t				overwrite:1;

	struct fbr_fullpath_name		filename;
};

struct fbr_iocmd_merge {
	unsigned int				magic;
#define FBR_IOCMD_MERGE_MAGIC			0x0C6E0087
};

typedef int (fbr_iocmd_f)(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
	const void *input, void *output);

int fbr_iocmd_pong(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
	const void *input, void *output);
int fbr_iocmd_import(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
	const void *input, void *output);
int fbr_iocmd_merge(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
	const void *input, void *output);

#endif /* _FBR_IOCMD_H_INCLUDED_ */
