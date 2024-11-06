/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef FBR_TEST_CMDS_H_INCLUDED
#define FBR_TEST_CMDS_H_INCLUDED

#ifndef FBR_TEST_CMD

#include "chttp.h"
#include <stddef.h>

#define FBR_TEST_MAX_PARAMS		16

// TODO move these out
#define CHTTP_TEST_MD5_BUFLEN		33
#define CHTTP_TEST_GZIP_BUFLEN		4096

struct chttp_test_server;
struct fbr_test_random;
struct chttp_test_dns;
struct chttp_test_tcp_pool;
struct chttp_gzip;

struct fbr_test_context {
	unsigned int			magic;
#define FBR_TEST_CONTEXT_MAGIC		0xAD98A6FF

	struct fbr_test			*test;

	struct chttp_context		chttp_static;
	struct chttp_context		*chttp;

	struct chttp_test_server	*server;
	struct fbr_test_random		*random;
	struct chttp_test_dns		*dns;
	struct chttp_test_tcp_pool	*tcp_pool;
	struct chttp_gzip		*gzip;
	char				gzip_buf[CHTTP_TEST_GZIP_BUFLEN];

	char				md5_server[CHTTP_TEST_MD5_BUFLEN];
	char				md5_client[CHTTP_TEST_MD5_BUFLEN];
};

struct fbr_test_cmd;

typedef void (fbr_test_cmd_f)(struct fbr_test_context *, struct fbr_test_cmd *);
typedef char *(fbr_test_var_f)(struct fbr_test_context *);

struct fbr_test_param {
	char				*value;
	size_t				len;

	unsigned int			v_const:1;
};

struct fbr_test_cmd {
	unsigned int			magic;
#define FBR_TEST_CMD_MAGIC		0x8F923F2E

	const char			*name;

	size_t				param_count;
	struct fbr_test_param		params[FBR_TEST_MAX_PARAMS];

	fbr_test_cmd_f			*func;

	unsigned int			async:1;
};

#define fbr_test_context_ok(context)					\
	do {								\
		assert(context);					\
		assert((context)->magic == FBR_TEST_CONTEXT_MAGIC);	\
	} while (0)
#define fbr_test_cmd_ok(cmd)						\
	do {								\
		assert(cmd);						\
		assert((cmd)->magic == FBR_TEST_CMD_MAGIC);		\
	} while (0)

#define FBR_TEST_CMD(cmd)		fbr_test_cmd_f fbr_test_cmd_##cmd;
#define FBR_TEST_VAR(var)		fbr_test_var_f fbr_test_var_##var;

#endif /* FBR_TEST_CMD */

#ifndef FBR_TEST_CMD
#error "FBR_TEST_CMD missing"
#endif
#ifndef FBR_TEST_VAR
#error "FBR_TEST_VAR missing"
#endif

FBR_TEST_CMD(fiber_test)
FBR_TEST_CMD(skip)
FBR_TEST_CMD(sleep_ms)
FBR_TEST_CMD(equal)
FBR_TEST_CMD(not_equal)

FBR_TEST_CMD(random_range)
FBR_TEST_VAR(random)

#undef FBR_TEST_CMD
#undef FBR_TEST_VAR

#endif /* FBR_TEST_CMDS_H_INCLUDED */
