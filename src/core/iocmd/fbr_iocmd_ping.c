/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "fiberfs.h"
#include "core/iocmd/fbr_iocmd.h"
#include "core/fs/fbr_fs.h"
#include "core/request/fbr_rlog.h"

int
fbr_iocmd_ping(const char *path)
{
	assert(path);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return 0;
	}

	struct fbr_iocmd_ping io_ping;
	static_ASSERT(sizeof(io_ping.version) >= sizeof(FIBERFS_VERSION));
	fbr_zero(&io_ping);
	io_ping.magic = FBR_IOCMD_PING_MAGIC;
	io_ping.ping = 1;
	fbr_strbcpy(io_ping.version, FIBERFS_VERSION);

	int ret = ioctl(fd, FBR_IOCMD_PING_REQ, &io_ping);

	int close_err = close(fd);
	assert_zero_dev(close_err);

	if (!ret && fbr_object_is_svalid(io_ping, FBR_IOCMD_PING_MAGIC) && io_ping.pong) {
		return 1;
	}

	return 0;
}

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
		return EINVAL;
	} else if (io_ping->ping != 1 || io_ping->pong) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR ping");
		return EINVAL;
	} else if (strcmp(io_ping->version, FIBERFS_VERSION)) {
		fbr_rlog(FBR_LOG_IOCMD_PING, "ERROR version");
		return EINVAL;
	}

	memcpy(io_pong, io_ping, sizeof(*io_ping));
	fbr_magic_check(io_pong, FBR_IOCMD_PING_MAGIC);

	io_pong->pong = 1;

	fbr_rlog(FBR_LOG_IOCMD_PING, "wrote PONG");

	return 0;
}
