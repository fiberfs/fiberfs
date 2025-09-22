/*
 * Copyright (c) 2021-2025 chttp
 * All rights reserved.
 *
 */

#ifndef _CHTTP_H_INCLUDED_
#define _CHTTP_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fiberfs.h"
#include "memory/chttp_dpage.h"
#include "network/chttp_network.h"

#define CHTTP_VERSION			"0.3.0"

#define	CHTTP_DEFAULT_METHOD		"GET"
#define CHTTP_DEFAULT_H_VERSION		CHTTP_H_VERSION_1_1
#define CHTTP_USER_AGENT		"chttp " CHTTP_VERSION


enum chttp_version {
	CHTTP_H_VERSION_DEFAULT = 0,
	CHTTP_H_VERSION_1_0,
	CHTTP_H_VERSION_1_1,
	CHTTP_H_VERSION_2_0,
	CHTTP_H_VERSION_3_0,
	_CHTTP_H_VERSION_ERROR
};

enum chttp_state {
	CHTTP_STATE_NONE = 0,
	CHTTP_STATE_INIT_METHOD,
	CHTTP_STATE_INIT_HEADER,
	CHTTP_STATE_SENT,
	CHTTP_STATE_HEADERS,
	CHTTP_STATE_BODY,
	CHTTP_STATE_IDLE,
	CHTTP_STATE_CLOSED,
	CHTTP_STATE_DONE,
	CHTTP_STATE_DONE_ERROR
};

enum chttp_error {
	CHTTP_ERR_NONE = 0,
	CHTTP_ERR_INIT,
	CHTTP_ERR_DNS,
	CHTTP_ERR_CONNECT,
	CHTTP_ERR_NETWORK,
	CHTTP_ERR_REQ_BODY,
	CHTTP_ERR_RESP_PARSE,
	CHTTP_ERR_RESP_LENGTH,
	CHTTP_ERR_RESP_CHUNK,
	CHTTP_ERR_RESP_BODY,
	CHTTP_ERR_TLS_INIT,
	CHTTP_ERR_TLS_HANDSHAKE,
	CHTTP_ERR_GZIP,
	CHTTP_ERR_BUFFER
};

struct chttp_context {
	unsigned int			magic;
#define CHTTP_CTX_MAGIC			0x81D0C9BA

	struct chttp_dpage		*dpage;
	struct chttp_dpage		*dpage_last;

	struct chttp_dpage_ptr		data_start;
	struct chttp_dpage_ptr		data_end;
	struct chttp_dpage_ptr		hostname;

	struct chttp_addr		addr;

	void				*gzip_priv;

	unsigned int			do_free:1;

	/* NOTE: see chttp_context_reset()
	   Anything below here is reset between requests
	 */

	enum chttp_state		state;
	enum chttp_version		version;
	enum chttp_error		error;

	int				status;
	long				length;

	unsigned int			is_head:1;
	unsigned int			has_host:1;
	unsigned int			close:1;
	unsigned int			chunked:1;
	unsigned int			seen_first:1;
	unsigned int			new_conn:1;
	unsigned int			gzip:1;
	unsigned int			want_100:1;

	uint8_t				_data[CHTTP_DPAGE_SIZE];
};

#define CHTTP_CTX_SIZE			(sizeof(struct chttp_context) - CHTTP_DPAGE_SIZE)

#define __chttp_attr_printf		__chttp_attr_printf_p(2)
#define __chttp_attr_printf_p(fpos)	__attribute__((__format__( \
						__printf__, (fpos), ((fpos) + 1))))

struct chttp_context *chttp_context_alloc(void);
void chttp_context_init(struct chttp_context *ctx);
struct chttp_context *chttp_context_init_buf(void *buffer, size_t buffer_len);
void chttp_context_reset(struct chttp_context *ctx);
void chttp_context_free(struct chttp_context *ctx);

void chttp_set_version(struct chttp_context *ctx, enum chttp_version version);
void chttp_set_method(struct chttp_context *ctx, const char *method);
void chttp_set_url(struct chttp_context *ctx, const char *url);

extern const char *CHTTP_HEADER_REASON;
void chttp_header_add(struct chttp_context *ctx, const char *name, const char *value);
void chttp_header_delete(struct chttp_context *ctx, const char *name);
void chttp_header_parse_response(struct chttp_context *ctx);
void chttp_header_parse_request(struct chttp_context *ctx);
const char *chttp_header_get(struct chttp_context *ctx, const char *name);
const char *chttp_header_get_pos(struct chttp_context *ctx, const char *name, size_t pos);
int chttp_header_endline(struct chttp_dpage *dpage, size_t start, size_t *mid, size_t *end,
	int has_return, int *binary);

void chttp_connect(struct chttp_context *ctx, const char *host, size_t host_len, int port,
	int tls);
void chttp_send(struct chttp_context *ctx);
void chttp_receive(struct chttp_context *ctx);
void chttp_error(struct chttp_context *ctx, enum chttp_error error);
void chttp_finish(struct chttp_context *ctx);

enum chttp_body_type {
	CHTTP_BODY_NONE = 0,
	CHTTP_BODY_REQUEST,
	CHTTP_BODY_RESPONSE,
};

void chttp_body_init(struct chttp_context *ctx, enum chttp_body_type type);
size_t chttp_body_read(struct chttp_context *ctx, void *buf, size_t buf_len);
size_t chttp_body_read_raw(struct chttp_context *ctx, void *buf, size_t buf_len);
void chttp_body_send(struct chttp_context *ctx, void *buf, size_t buf_len);

void chttp_context_debug(struct chttp_context *ctx);
void chttp_dpage_debug(struct chttp_dpage *dpage);
void chttp_print_hex(void *buf, size_t buf_len);
const char *chttp_error_msg(struct chttp_context *ctx);
void chttp_sa_string(const struct sockaddr *sa, char *buf, size_t buf_len, int *port);
size_t chttp_make_chunk(char *buffer, unsigned int buffer_len);

#define chttp_context_ok(ctx)		fbr_magic_check(ctx, CHTTP_CTX_MAGIC)

#endif /* _CHTTP_H_INCLUDED_ */
