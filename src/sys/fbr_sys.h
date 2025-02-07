/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_FS_H_INCLUDED_
#define _FBR_FS_H_INCLUDED_

int fbr_fs_exists(const char *path);
int fbr_fs_isdir(const char *path);
void fbr_rmdir(const char *path);

#endif /* _FBR_FS_H_INCLUDED_ */
