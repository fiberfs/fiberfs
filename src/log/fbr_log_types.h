/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_LOG_TYPES_H_INCLUDED_
#define _FBR_LOG_TYPES_H_INCLUDED_

enum fbr_request_ids {
	FBR_REQUEST_ID_NONE = 0,
	FBR_REQUEST_ID_DEBUG,
	__FBR_REQUEST_ID_MAX
};

enum fbr_log_type {
	__FBR_LOG_TYPE_NONE = 0,
	FBR_LOG_DEBUG,
	__FBR_LOG_TYPE_END
};

#endif /* _FBR_LOG_TYPES_H_INCLUDED_ */
