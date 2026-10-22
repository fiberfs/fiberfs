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
#include "core/iocmd/fbr_iocmd.h"
#include "core/fs/fbr_fs.h"
#include "core/request/fbr_rlog.h"

int
fbr_iocmd_import(const char *path)
{
	assert(path);
	assert_zero(fbr_request_get());

	int error = fbr_check_name(path);
	if (error) {
		return 0;
	}

	int absolute = 0;
	if (path[0] == '/') {
		absolute = 1;
	}

	struct fbr_path_name fullpath;
	fbr_path_name_init(&fullpath, path);

	size_t fullpath_len = fullpath.length;
	fbr_path_name_parent(&fullpath, &fullpath);

	const char *filename = fullpath.name + fullpath.length + 1;
	char dirpath[FBR_PATH_MAX];

	if (!fullpath.length && absolute) {
		fbr_strbcpy(dirpath, "/");
	} else if (!fullpath.length) {
		fbr_strbcpy(dirpath, ".");
		filename--;
	} else {
		if (fullpath.length + 1 >= fullpath_len) {
			return 0;
		}

		fbr_bprintf(dirpath, "%.*s", (int)fullpath.length, fullpath.name);
	}

	size_t filename_len = strlen(filename);
	if (!filename_len || !strcmp(filename, ".") || !strcmp(filename, "..")) {
		return 0;
	}

	int ret = fbr_iocmd_ping(dirpath);
	if (!ret) {
		return 0;
	}

	fbr_rlog(FBR_LOG_IOCMD_IMPORT, "dir: '%s' file: '%s'", dirpath, filename);

	int fd = open(dirpath, O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		return 0;
	}

	struct fbr_iocmd_import io_import;
	fbr_zero(&io_import);
	io_import.magic = FBR_IOCMD_IMPORT_MAGIC;
	fbr_strbcpy(io_import.filename.data, filename);
	fbr_path_name_init(&io_import.filename.path, io_import.filename.data);
	assert_dev(io_import.filename.path.length == filename_len);

	error = ioctl(fd, FBR_IOCMD_IMPORT_REQ, &io_import);

	assert_zero_dev(close(fd));

	if (error) {
		return 0;
	}

	return 1;
}

int
fbr_iocmd_import_request(struct fbr_fs *fs, struct fbr_file *file, unsigned long command,
   const void *input, void *output)
{
	fbr_fs_ok(fs);
	fbr_file_ok(file);
	assert(command == FBR_IOCMD_IMPORT_REQ);
	assert(input);
	assert_zero(output);
	assert(fbr_request_get());

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
