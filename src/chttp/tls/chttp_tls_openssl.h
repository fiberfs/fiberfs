/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _CHTTP_TLS_OPENSSL_H_INCLUDED_
#define _CHTTP_TLS_OPENSSL_H_INCLUDED_

#ifdef CHTTP_OPENSSL

#include <stddef.h>

struct chttp_context;
struct chttp_addr;

void chttp_openssl_free(void);
void chttp_openssl_connect(struct chttp_addr *addr);
void chttp_openssl_accept(struct chttp_addr *addr);
void chttp_openssl_close(struct chttp_addr *addr);
void chttp_openssl_write(struct chttp_addr *addr, const void *buf, size_t buf_len);
size_t chttp_openssl_read(struct chttp_addr *addr, void *buf, size_t buf_len);

#endif /* CHTTP_OPENSSL */

#endif /* _CHTTP_TLS_OPENSSL_H_INCLUDED_ */
