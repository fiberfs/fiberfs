/*
 * Copyright (c) 2024-2026 FiberFS LLC
 *
 */

#ifndef _CHTTP_TLS_H_INCLUDED_
#define _CHTTP_TLS_H_INCLUDED_

#include <stddef.h>

struct chttp_context;
struct chttp_addr;

int chttp_tls_enabled(void);
void chttp_tls_free(void);
void chttp_tls_connect(struct chttp_addr *addr);
void chttp_tls_accept(struct chttp_addr *addr);
void chttp_tls_close(struct chttp_addr *addr);
void chttp_tls_write(struct chttp_addr *addr, const void *buf, size_t buf_len);
size_t chttp_tls_read(struct chttp_addr *addr, void *buf, size_t buf_len);

#endif /* _CHTTP_TLS_H_INCLUDED_ */
