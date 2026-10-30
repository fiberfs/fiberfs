/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_cmd.h"
#include "fbr_iocmd.h"
#include "core/fs/fbr_path.h"
#include "utils/fbr_sys.h"

int
fbr_cmd_ping(const char *path, double *timing)
{
	assert(path);

	if (timing) {
		*timing = 0;
	}

	double time_start = fbr_get_time();

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return errno ? errno : EIO;
	}

	struct fbr_iocmd_ping io_ping;
	static_ASSERT(sizeof(io_ping.version) >= sizeof(FIBERFS_VERSION));
	fbr_zero(&io_ping);
	io_ping.magic = FBR_IOCMD_PING_MAGIC;
	io_ping.ping = 1;
	fbr_strbcpy(io_ping.version, FIBERFS_VERSION);

	int ret = ioctl(fd, FBR_IOCMD_PING_REQ, &io_ping);

	assert_zero_dev(close(fd));

	if (timing) {
		*timing = fbr_get_time() - time_start;
	}

	if (!ret && fbr_object_is_svalid(io_ping, FBR_IOCMD_PING_MAGIC) && io_ping.pong) {
		return 0;
	} else if (!ret) {
		ret = EIO;
	}

	return ret;
}

void
fbr_iocmd_import_init(struct fbr_iocmd_import *io_import)
{
	assert(io_import);

	fbr_zero(io_import);
	io_import->magic = FBR_IOCMD_IMPORT_MAGIC;
}

int
fbr_cmd_import(const char *path, int overwrite)
{
	assert(path);

	struct fbr_fullpath_name dirpath;
	const char *name = fbr_fullpath_split(path, &dirpath);
	assert(name);

	struct fbr_path_name filename;
	fbr_path_name_init(&filename, name);

	int ret = fbr_check_name(&dirpath.path, &filename);
	if (ret) {
		return ret;
	}

	ret = fbr_cmd_ping(dirpath.path.name, NULL);
	if (ret) {
		return ret;
	}

	int fd = open(dirpath.path.name, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		return errno ? errno : EIO;
	}

	struct fbr_iocmd_import io_import;
	fbr_iocmd_import_init(&io_import);
	io_import.filename.path.length = fbr_strbcpy(io_import.filename.data, filename.name);
	io_import.overwrite = overwrite > 0 ? 1 : 0;
	io_import.external = 1;

	ret = ioctl(fd, FBR_IOCMD_IMPORT_REQ, &io_import);

	assert_zero_dev(close(fd));

	if (ret) {
		return errno ? errno : EIO;
	}

	return 0;
}

int
fbr_cmd_merge(const char *path)
{
	assert(path);

	if (fbr_sys_isdir(path)) {
		return EISDIR;
	}

	int ret = fbr_cmd_ping(path, NULL);
	if (ret) {
		return ret;
	}

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return errno ? errno : EIO;
	}

	struct fbr_iocmd_merge io_merge;
	fbr_zero(&io_merge);
	io_merge.magic = FBR_IOCMD_MERGE_MAGIC;

	ret = ioctl(fd, FBR_IOCMD_MERGE_REQ, &io_merge);

	assert_zero_dev(close(fd));

	if (ret) {
		return errno ? errno : EIO;
	}

	return 0;
}
