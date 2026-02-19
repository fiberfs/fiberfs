/*
 * Copyright (c) 2021-2026 FiberFS LLC
 * All rights reserved.
 *
 * A streaming splice friendly zero memory allocation HTTP library
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
#define CHTTP_USER_AGENT		"fiberfs chttp " CHTTP_VERSION
#define CHTTP_MAX_HEADER_BYTES		(10 * 1024)


enum chttp_version {
	CHTTP_H_VERSION_DEFAULT = 0,
	CHTTP_H_VERSION_1_0,
	CHTTP_H_VERSION_1_1,
	CHTTP_H_VERSION_2_0,
	CHTTP_H_VERSION_3_0,
	_CHTTP_H_VERSION_ERROR
};

#define CHTTP_ENUM_STATE								\
	FBR_ENUM_NAME(chttp_state)							\
		FBR_ENUM_VALUES_INIT(CHTTP_STATE_NONE, "none", 0)			\
		FBR_ENUM_VALUES(CHTTP_STATE_INIT_METHOD, "init method")			\
		FBR_ENUM_VALUES(CHTTP_STATE_INIT_HEADER,"init header")			\
		FBR_ENUM_VALUES(CHTTP_STATE_SENT, "sent")				\
		FBR_ENUM_VALUES(CHTTP_STATE_HEADERS, "headers")				\
		FBR_ENUM_VALUES(CHTTP_STATE_BODY, "body")				\
		FBR_ENUM_VALUES(CHTTP_STATE_IDLE, "idle")				\
		FBR_ENUM_VALUES(CHTTP_STATE_CLOSED, "closed")				\
		FBR_ENUM_VALUES(CHTTP_STATE_DONE, "done")				\
		FBR_ENUM_VALUES(CHTTP_STATE_DONE_ERROR, "error")			\
	FBR_ENUM_END("unknown")

#define CHTTP_ERROR_STATE								\
	FBR_ENUM_NAMES(chttp_error, _error_string)							\
		FBR_ENUM_VALUES_INIT(CHTTP_ERR_NONE, "none", 0)				\
		FBR_ENUM_VALUES(CHTTP_ERR_INIT, "initialization")			\
		FBR_ENUM_VALUES(CHTTP_ERR_DNS, "DNS error")				\
		FBR_ENUM_VALUES(CHTTP_ERR_CONNECT, "cannot make connection")		\
		FBR_ENUM_VALUES(CHTTP_ERR_NETWORK, "network error")			\
		FBR_ENUM_VALUES(CHTTP_ERR_REQ_BODY, "bad request body")			\
		FBR_ENUM_VALUES(CHTTP_ERR_RESP_PARSE, "cannot parse response")		\
		FBR_ENUM_VALUES(CHTTP_ERR_RESP_LENGTH, "cannot parse resp body length")	\
		FBR_ENUM_VALUES(CHTTP_ERR_RESP_CHUNK, "cannot parse resp body chunk")	\
		FBR_ENUM_VALUES(CHTTP_ERR_RESP_BODY, "cannot parse resp body")		\
		FBR_ENUM_VALUES(CHTTP_ERR_TLS_INIT, "TLS initialization error")		\
		FBR_ENUM_VALUES(CHTTP_ERR_TLS_HANDSHAKE, "TLS handshake error")		\
		FBR_ENUM_VALUES(CHTTP_ERR_GZIP, "gzip error")				\
		FBR_ENUM_VALUES(CHTTP_ERR_BUFFER, "buffer error")			\
	FBR_ENUM_END("unknown")

#include "utils/fbr_enum_define.h"
CHTTP_ENUM_STATE;
CHTTP_ERROR_STATE;

enum chttp_request_type {
	CHTTP_REQUEST_NONE = 0,
	CHTTP_REQUEST,
	CHTTP_RESPONSE,
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
	unsigned int			raw_send:1;
	unsigned int			chunked:1;
	unsigned int			seen_first:1;
	unsigned int			new_conn:1;
	unsigned int			gzip:1;
	unsigned int			want_100:1;
	unsigned int			sent_100:1;
	unsigned int			request:1;
	unsigned int			pipeline:1;

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

void chttp_header_add(struct chttp_context *ctx, const char *name, const char *value);
void chttp_header_delete(struct chttp_context *ctx, const char *name);
void chttp_header_parse(struct chttp_context *ctx, enum chttp_request_type type);
const char *chttp_header_get(struct chttp_context *ctx, const char *name);
const char *chttp_header_get_pos(struct chttp_context *ctx, const char *name, size_t pos);
const char *chttp_header_get_reason(struct chttp_context *ctx);
const char *chttp_header_get_method(struct chttp_context *ctx);
const char *chttp_header_get_url(struct chttp_context *ctx);
const char *chttp_header_get_version(struct chttp_context *ctx);
int chttp_header_endline(struct chttp_dpage *dpage, size_t start, size_t *mid, size_t *end,
	int has_return, int *binary);

void chttp_connect(struct chttp_context *ctx, const char *host, size_t host_len, int port,
	int tls);
void chttp_send(struct chttp_context *ctx);
void chttp_receive(struct chttp_context *ctx);
void chttp_parse(struct chttp_context *ctx, enum chttp_request_type type);
void chttp_error(struct chttp_context *ctx, enum chttp_error error);
void chttp_finish(struct chttp_context *ctx);

void chttp_body_init(struct chttp_context *ctx, enum chttp_request_type type);
size_t chttp_body_buffered(struct chttp_context *ctx);
size_t chttp_body_read(struct chttp_context *ctx, void *buf, size_t buf_len);
size_t chttp_body_read_raw(struct chttp_context *ctx, void *buf, size_t buf_len);
void chttp_body_send(struct chttp_context *ctx, void *buf, size_t buf_len);

void chttp_context_debug(struct chttp_context *ctx);
void chttp_dpage_debug(struct chttp_dpage *dpage);
void chttp_print_hex(void *buf, size_t buf_len);
const char *chttp_error_msg(struct chttp_context *ctx);
const char *chttp_state_string(enum chttp_state state);
void chttp_sa_string(const struct sockaddr *sa, char *buf, size_t buf_len, int *port);
size_t chttp_make_chunk(char *buffer, size_t buffer_len, unsigned int chunk_len);

#include "utils/fbr_enum_string_declare.h"
CHTTP_ENUM_STATE

#define chttp_context_ok(ctx)	\
	fbr_magic_check(ctx, CHTTP_CTX_MAGIC)

#endif /* _CHTTP_H_INCLUDED_ */
