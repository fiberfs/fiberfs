/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_CSTORE_SERVER_H_INCLUDED_
#define _FBR_CSTORE_SERVER_H_INCLUDED_

struct fbr_cstore_server {
	int				valid;
};

struct fbr_cstore;

void fbr_cstore_server_init(struct fbr_cstore *cstore);
void fbr_cstore_server_free(struct fbr_cstore *cstore);

#endif /* _FBR_CSTORE_SERVER_H_INCLUDED_ */
