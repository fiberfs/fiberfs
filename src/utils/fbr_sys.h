/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_SYS_H_INCLUDED_
#define _FBR_SYS_H_INCLUDED_

#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

struct FTW;
typedef int (*fbr_nftw_func_t) (const char *filename, const struct stat *stat, int flag,
	struct FTW *info);

int fbr_sys_exists(const char *path);
int fbr_sys_isdir(const char *path);
void fbr_sys_rmdir(const char *path);
int fbr_sys_nftw(const char *path, fbr_nftw_func_t func);
size_t fbr_sys_write(int fd, const void *buf, size_t buf_len);
ssize_t fbr_sys_read(int fd, void *buf, size_t buf_len);
int fbr_mkdirs(const char *path);

#endif /* _FBR_SYS_H_INCLUDED_ */
