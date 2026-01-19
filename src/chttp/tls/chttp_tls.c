/*
 * Copyright (c) 2024-2026 FiberFS LLC
 *
 * TODO look at aws-lc
 *
 */

#include "chttp.h"
#include "chttp_tls_openssl.h"

int
chttp_tls_enabled(void)
{
#ifdef CHTTP_OPENSSL
	return 1;
#else
	return 0;
#endif
}

void
chttp_tls_free(void)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_free();
#endif
}

void
chttp_tls_connect(struct chttp_addr *addr)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_connect(addr);
#else
	(void)addr;
	fbr_ABORT("TLS not configured");
#endif
}

void
chttp_tls_accept(struct chttp_addr *addr)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_accept(addr);
#else
	(void)addr;
	fbr_ABORT("TLS not configured");
#endif
}

void
chttp_tls_close(struct chttp_addr *addr)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_close(addr);
#else
	(void)addr;
	fbr_ABORT("TLS not configured");
#endif
}

void
chttp_tls_write(struct chttp_addr *addr, const void *buf, size_t buf_len)
{
#ifdef CHTTP_OPENSSL
	chttp_openssl_write(addr, buf, buf_len);
#else
	(void)addr;
	(void)buf;
	(void)buf_len;
	fbr_ABORT("TLS not configured");
#endif
}

size_t
chttp_tls_read(struct chttp_addr *addr, void *buf, size_t buf_len)
{
#ifdef CHTTP_OPENSSL
	return chttp_openssl_read(addr, buf, buf_len);
#else
	(void)addr;
	(void)buf;
	(void)buf_len;
	fbr_ABORT("TLS not configured");
	return 0;
#endif
}
