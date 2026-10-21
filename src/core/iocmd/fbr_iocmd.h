/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_IO_CMD_H_INCLUDED_
#define _FBR_IO_CMD_H_INCLUDED_

#include <sys/ioctl.h>

#include "core/fs/fbr_fs.h"
#include "core/fs/fbr_path.h"

typedef int (fbr_iocmd_f)(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
	const void *input, void *output);

struct fbr_iocmd_route {
	unsigned long				command;
	fbr_iocmd_f				*callback;
};

struct fbr_iocmd_ping {
	unsigned int				magic;
#define FBR_IOCMD_PING_MAGIC			0x8D5BB37C

	fbr_bitflag_t				ping:1;
	fbr_bitflag_t				pong:1;

	char					version[64];
};

#define FBR_IOCMD_PING_REQ			_IOWR('P', 1, struct fbr_iocmd_ping)

extern struct fbr_iocmd_route FBR_IOCMD_ROUTES[1];

int fbr_iocmd_ping(const char *path);
int fbr_iocmd_pong(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
	const void *input, void *output);

#endif /* _FBR_OPERATIONS_H_INCLUDED_ */
