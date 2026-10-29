/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>
#include <string.h>

#include "fiberfs.h"
#include "fbr_iocmd.h"
#include "core/fs/fbr_fs.h"
#include "core/request/fbr_rlog.h"

int
fbr_iocmd_pong(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
   const void *input, void *output)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(command == FBR_IOCMD_PING_REQ);
	assert(input);
	assert(output);

	const struct fbr_iocmd_ping *io_ping = input;
	struct fbr_iocmd_ping *io_pong = output;

	fbr_rlog(FBR_LOG_IOCMD_PING, "received PING");

	if (!fbr_object_is_valid(io_ping, FBR_IOCMD_PING_MAGIC)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR magic");
		return EIO;
	} else if (io_ping->ping != 1 || io_ping->pong) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR ping");
		return EIO;
	} else if (strcmp(io_ping->version, FIBERFS_VERSION)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR version");
		return EACCES;
	}

	memcpy(io_pong, io_ping, sizeof(*io_ping));
	fbr_magic_check(io_pong, FBR_IOCMD_PING_MAGIC);

	io_pong->pong = 1;

	fbr_rlog(FBR_LOG_IOCMD_PING, "wrote PONG");

	return 0;
}
