/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_S3_H_INCLUDED_
#define _FBR_CSTORE_S3_H_INCLUDED_

struct fbr_cstore_s3 {
	const char		host[256];
	const char		prefix[256];

	int			port;

	unsigned int		enabled:1;
	unsigned int		tls:1;
};

void fbr_cstore_s3_wbuffer_write(struct fbr_cstore *cstore, struct chttp_context *request,
	const char *path, struct fbr_wbuffer *wbuffer);
void fbr_cstore_s3_wbuffer_finish(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct chttp_context *request, struct fbr_wbuffer *wbuffer, int error);
void fbr_cstore_s3_chunk_read(struct fbr_fs *fs, struct fbr_cstore *cstore,
	struct fbr_file *file, struct fbr_chunk *chunk);

#endif /* _FBR_CSTORE_S3_H_INCLUDED_ */
