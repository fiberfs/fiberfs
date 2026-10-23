/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_CMD_H_INCLUDED_
#define _FBR_CMD_H_INCLUDED_

int fbr_cmd_ping(const char *path);
int fbr_cmd_import(const char *path, int overwrite);

#endif /* _FBR_CMD_H_INCLUDED_ */
