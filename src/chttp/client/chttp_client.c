/*
 * Copyright (c) 2021 chttp
 *
 */

#include "chttp.h"
#include "compress/fbr_gzip.h"
#include "network/chttp_tcp_pool.h"
#include "tls/chttp_tls.h"

#include <assert.h>
#include <stdio.h>

int
main(int argc, char **argv)
{
	struct chttp_context *context, scontext, *tlsc;
	char ctx_buf[2000], ctx_buf2[CHTTP_CTX_SIZE + 1];
	char body_buf[100], gzip_buf[200];
	size_t body_len;
	struct fbr_gzip gzip;

	(void)argc;
	(void)argv;

	printf("chttp_client %s\n", CHTTP_VERSION);

	printf("sizeof(struct chttp_ctx)=%zu\n", CHTTP_CTX_SIZE);
	printf("sizeof(struct chttp_dpage)=%zu\n", sizeof(struct chttp_dpage));

	printf("CHTTP_DPAGE_SIZE=%zu\n", CHTTP_DPAGE_SIZE);
	printf("sizeof(context->_data)=%zu\n", sizeof(((struct chttp_context *)0)->_data));
	assert(CHTTP_DPAGE_SIZE == sizeof(((struct chttp_context *)0)->_data));

	//_DEBUG_CHTTP_DPAGE_MIN_SIZE = 12;

	// dynamic
	printf("\n*** dynamic test\n\n");

	context = chttp_context_alloc();

	chttp_set_version(context, CHTTP_H_VERSION_1_1);
	chttp_set_method(context, "GET");
	chttp_set_url(context, "/abc");
	chttp_header_add(context, "header1", "abc123");
	chttp_header_add(context, "header1", "duplicate");
	chttp_header_add(context, "header2", "XYZZZZ");
	chttp_header_add(context, "header1", "again, why");
	chttp_header_add(context, "header3", "very, imortant; information");
	chttp_context_debug(context);
	chttp_header_delete(context, "header1");
	chttp_header_delete(context, "header2");
	chttp_connect(context, "ec2.rezsoft.org", strlen("ec2.rezsoft.org"), 80, 0);
	chttp_send(context);
	chttp_context_debug(context);
	chttp_receive(context);
	chttp_context_debug(context);
	do {
		body_len = chttp_body_read(context, body_buf, sizeof(body_buf));
		printf("***BODY*** (%zu, %d)\n", body_len, context->state);
		chttp_print_hex(body_buf, body_len);
	} while (body_len);
	chttp_context_free(context);

	// static
	printf("\n*** static test\n\n");
	chttp_context_init(&scontext);
	chttp_set_url(&scontext, "/");
	chttp_header_add(&scontext, "a", "1");
	chttp_header_add(&scontext, "a", "1");
	chttp_context_debug(&scontext);
	chttp_header_delete(&scontext, "x");
	chttp_header_delete(&scontext, "a");
	chttp_header_add(&scontext, "x", "2");
	chttp_connect(&scontext, "textglass.org", strlen("textglass.org"), 80, 0);
	chttp_send(&scontext);
	chttp_context_debug(&scontext);
	chttp_receive(&scontext);
	chttp_context_debug(&scontext);
	do {
		body_len = chttp_body_read(&scontext, body_buf, sizeof(body_buf));
		printf("***BODY*** (%zu, %d)\n", body_len, scontext.state);
		chttp_print_hex(body_buf, body_len);
	} while (body_len);
	chttp_context_free(&scontext);

	// custom
	printf("\n*** custom test\n\n");
	context = chttp_context_init_buf(ctx_buf, sizeof(ctx_buf));
	chttp_set_url(context, "/123-custom");
	chttp_context_debug(context);
	chttp_context_free(context);

	// custom2
	printf("\n*** custom2 test\n\n");
	context = chttp_context_init_buf(ctx_buf2, sizeof(ctx_buf2));
	chttp_set_url(context, "/123-nodpage");
	chttp_context_debug(context);
	chttp_context_free(context);

	// tls
	printf("\n*** tls test\n\n");
	tlsc = chttp_context_alloc();
	chttp_set_method(tlsc, "GET");
	chttp_set_url(tlsc, "/");
	chttp_context_debug(tlsc);
	chttp_connect(tlsc, "nulltech.systems", strlen("nulltech.systems"), 443, 1);
	chttp_send(tlsc);
	chttp_context_debug(tlsc);
	chttp_receive(tlsc);
	chttp_context_debug(tlsc);
	do {
		body_len = chttp_body_read(tlsc, body_buf, sizeof(body_buf));
		printf("***BODY*** (%zu, %d)\n", body_len, tlsc->state);
		chttp_print_hex(body_buf, body_len);
	} while (body_len);
	chttp_context_free(tlsc);

	// gzip
	printf("\n*** gzip test\n\n");

	context = chttp_context_alloc();

	chttp_set_method(context, "GET");
	chttp_set_url(context, "/");
	chttp_header_add(context, "Accept-Encoding", "gzip");
	chttp_connect(context, "ec2.rezsoft.org", strlen("ec2.rezsoft.org"), 80, 0);
	chttp_send(context);
	chttp_receive(context);
	chttp_context_debug(context);
	fbr_gzip_inflate_init(&gzip);
	chttp_gzip_register(context, &gzip, gzip_buf, sizeof(gzip_buf));
	do {
		body_len = chttp_body_read(context, body_buf, sizeof(body_buf));
		printf("***BODY*** (%zu, %d)\n", body_len, context->state);
		chttp_print_hex(body_buf, body_len);
	} while (body_len);
	chttp_context_free(context);

	chttp_tcp_pool_close();
	chttp_tls_free();

	return (0);
}

// Required for fiber asserting
void
fbr_context_abort(void)
{
}
