/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_MAIN_H_INCLUDED_
#define _FBR_MAIN_H_INCLUDED_

#define FBR_MOUNT_LOOP_MS		25

extern int FBR_MAIN_STOP;

void fbr_main_usage(void);
int fiberfs_mount(const char *fiberfs_conf, const char *mount_path);

#endif /* _FBR_MAIN_H_INCLUDED_ */
