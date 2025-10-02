/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_S3_H_INCLUDED_
#define _FBR_CSTORE_S3_H_INCLUDED_

struct fbr_cstore_s3 {
	const char		host[1024];
	const char		prefix[256];

	int			port;

	unsigned int		tls;
};

#endif /* _FBR_CSTORE_S3_H_INCLUDED_ */
