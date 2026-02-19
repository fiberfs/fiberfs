/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "chttp.h"

void
chttp_context_debug(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	printf("chttp_ctx state=%d (%s) error=%d (%s) version=%d data_last=%p\n"
		"\tdata_start=%p:%zu:%zu data_end=%p:%zu:%zu\n"
		"\thostname=%p:%zu:%zu\n"
		"\tstatus=%d length=%ld do_free=%u has_host=%u close=%u chunked=%u\n"
		"\tgzip=%u tls=%d reused=%d pipeline=%u time=%lf\n",
		ctx->state, chttp_state_string(ctx->state), ctx->error, chttp_error_msg(ctx),
		ctx->version, (void*)ctx->dpage_last,
		(void*)ctx->data_start.dpage, ctx->data_start.offset, ctx->data_start.length,
		(void*)ctx->data_end.dpage, ctx->data_end.offset, ctx->data_end.length,
		(void*)ctx->hostname.dpage, ctx->hostname.offset, ctx->hostname.length,
		ctx->status, ctx->length, ctx->do_free, ctx->has_host, ctx->close, ctx->chunked,
		ctx->gzip, ctx->addr.tls, ctx->addr.reused, ctx->pipeline,
		fbr_get_time() - ctx->addr.time_start);

	chttp_dpage_debug(ctx->dpage);
}

void
chttp_dpage_debug(struct chttp_dpage *dpage)
{
	while (dpage) {
		chttp_dpage_ok(dpage);

		printf("\tchttp_dpage free=%u length=%zu offset=%zu ptr=%p (%p)\n",
			dpage->free, dpage->length, dpage->offset, (void*)dpage, (void*)dpage->data);

		if (dpage->offset) {
			chttp_print_hex(dpage->data, dpage->offset);
		}

		dpage = dpage->next;
	}
}

void
chttp_print_hex(void *buf, size_t buf_len)
{
	uint8_t *buffer;
	size_t i;

	assert(buf);

	buffer = buf;

	printf("\t> ");

	for (i = 0; i < buf_len; i++) {
		if (buffer[i] >= ' ' && buffer[i] <= '~') {
			printf("%c", buffer[i]);
			continue;
		}

		switch(buffer[i]) {
			case '\r':
				printf("\\r");
				break;
			case '\n':
				if (i == buf_len - 1) {
					printf("\\n");
				} else {
					printf("\\n\n\t> ");
				}
				break;
			case '\\':
				printf("\\\\");
				break;
			default:
				printf("\\0x%x", buffer[i]);
		}
	}

	printf("\n");
}

#include "utils/fbr_enum_string.h"
CHTTP_ENUM_STATE
static CHTTP_ERROR_STATE

const char *
chttp_error_msg(struct chttp_context *ctx)
{
	chttp_context_ok(ctx);

	return _error_string(ctx->error);
}

void
chttp_sa_string(const struct sockaddr *sa, char *buf, size_t buf_len, int *port)
{
	assert(sa);
	assert(buf);
	assert(buf_len);
	assert(port);

	buf[0] = '\0';
	*port = -1;

	switch (sa->sa_family) {
		case AF_INET:
			assert(inet_ntop(AF_INET, &(((struct sockaddr_in*)sa)->sin_addr),
				buf, buf_len));
			*port = ntohs(((struct sockaddr_in*)sa)->sin_port);
			break;
		case AF_INET6:
			assert(inet_ntop(AF_INET6, &(((struct sockaddr_in6*)sa)->sin6_addr),
				buf, buf_len));
			*port = ntohs(((struct sockaddr_in6*)sa)->sin6_port);
			break;
		default:
			fbr_ABORT("Invalid sockaddr family");
	}
}

size_t
chttp_make_chunk(char *buffer, size_t buffer_len, unsigned int chunk_len)
{
	size_t ret;

	assert(buffer);
	assert(buffer_len);

	ret = snprintf(buffer, buffer_len, "%x", chunk_len);

	if (ret + 2 > buffer_len) {
		return 0;
	}

	buffer[ret++] = '\r';
	buffer[ret++] = '\n';

	assert_dev(ret <= buffer_len);

	return ret;
}
