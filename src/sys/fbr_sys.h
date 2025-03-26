/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FBR_SYS_H_INCLUDED_
#define _FBR_SYS_H_INCLUDED_

int fbr_sys_exists(const char *path);
int fbr_sys_isdir(const char *path);
void fbr_sys_rmdir(const char *path);

#endif /* _FBR_SYS_H_INCLUDED_ */
