/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_LOG_TYPES_H_INCLUDED_
#define _FBR_LOG_TYPES_H_INCLUDED_

enum fbr_request_ids {
	FBR_REQID_NONE = 0,
	FBR_REQID_TEST,
	FBR_REQID_DEBUG,
	FBR_REQID_FUSE,
	__FBR_REQID_MAX
};

enum fbr_log_type {
	__FBR_LOG_TYPE_NONE = 0,
	FBR_LOG_TEST,
	FBR_LOG_DEBUG,
	FBR_LOG_ERROR,
	FBR_LOG_FUSE,
	__FBR_LOG_TYPE_END
};

#endif /* _FBR_LOG_TYPES_H_INCLUDED_ */
