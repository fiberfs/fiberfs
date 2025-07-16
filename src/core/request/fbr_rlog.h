/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_RLOG_H_INCLUDED_
#define _FBR_RLOG_H_INCLUDED_

#include <stddef.h>

#include "fiberfs.h"
#include "log/fbr_log.h"

#define FBR_RLOG_MIN_SIZE			1024

struct fbr_rlog {
	unsigned int				magic;
#define FBR_RLOG_MAGIC				0x2F1D5206

	unsigned int				lines;

	fbr_log_data_t				*log_end;
	fbr_log_data_t				*log_pos;

	fbr_log_data_t				data[];
};

struct fbr_request;

void fbr_rlog_workspace_alloc(struct fbr_request *request);
void __fbr_attr_printf(2) fbr_rlog(enum fbr_log_type type, const char *fmt, ...);
void fbr_rlog_free(struct fbr_rlog **rlog);

#define fbr_rlog_ok(rlog)			fbr_magic_check(rlog, FBR_RLOG_MAGIC)

#endif /* _FBR_RLOG_H_INCLUDED_ */
