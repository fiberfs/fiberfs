/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "fiberfs.h"
#include "fbr_cmd.h"
#include "fbr_iocmd.h"
#include "core/fs/fbr_fs.h"
#include "core/request/fbr_rlog.h"

int
fbr_cmd_import(const char *path)
{
	assert(path);
	assert_zero(fbr_request_get());

	int error = fbr_check_name(path);
	if (error) {
		return 0;
	}

	struct fbr_fullpath_name dirpath;
	const char *filename = fbr_fullpath_split(path, &dirpath);
	assert(filename);

	size_t filename_len = strlen(filename);
	if (!filename_len || !strcmp(filename, ".") || !strcmp(filename, "..")) {
		return 0;
	}

	int ret = fbr_cmd_ping(dirpath.path.name);
	if (!ret) {
		return 0;
	}

	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "dir: '%s' file: '%s'", dirpath.path.name, filename);

	int fd = open(dirpath.path.name, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		return 0;
	}

	struct fbr_iocmd_import io_import;
	fbr_zero(&io_import);
	io_import.magic = FBR_IOCMD_IMPORT_MAGIC;
	fbr_fullpath_init(&io_import.filename);
	io_import.filename.path.length = fbr_strbcpy(io_import.filename.data, filename);

	error = ioctl(fd, FBR_IOCMD_IMPORT_REQ, &io_import);

	assert_zero_dev(close(fd));

	if (error) {
		return 0;
	}

	return 1;
}

int
fbr_iocmd_import(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
   const void *input, void *output)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(command == FBR_IOCMD_IMPORT_REQ);
	assert(input);
	assert_zero(output);

	const struct fbr_iocmd_import *io_import = input;

	if (!fbr_object_is_valid(io_import, FBR_IOCMD_IMPORT_MAGIC)) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR magic");
		return EINVAL;
	} else if (!io_import->filename.path.length) {
		fbr_rlog(FBR_LOG_IOCMD_IMPORT, "ERROR length");
		return EINVAL;
	}

	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "request: '%s'", io_import->filename.path.name);

	return 0;
}
