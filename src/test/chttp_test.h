/*
 * Copyright (c) 2021 chttp
 *
 */

#ifndef _CHTTP_TEST_H_INCLUDED_
#define _CHTTP_TEST_H_INCLUDED_

#include "chttp.h"
#include "data/queue.h"
#include "data/tree.h"
#include "test/chttp_test_cmds.h"

#include <stdio.h>
#include <pthread.h>

enum chttp_test_verbocity {
	CHTTP_LOG_FORCE = -2,
	CHTTP_LOG_ROOT = -1,
	CHTTP_LOG_NONE = 0,
	CHTTP_LOG_VERBOSE,
	CHTTP_LOG_VERY_VERBOSE
};

struct chttp_test_cmdentry {
	unsigned int				magic;
#define CHTTP_TEST_ENTRY_MAGIC			0x52C66713

	RB_ENTRY(chttp_test_cmdentry)		entry;

	const char				*name;
	chttp_test_cmd_f			*cmd_func;
	chttp_test_var_f			*var_func;

	unsigned int				is_cmd:1;
	unsigned int				is_var:1;
};

RB_HEAD(chttp_test_tree, chttp_test_cmdentry);

struct chttp_test;

typedef void (chttp_test_finish_f)(struct chttp_test_context*);

struct chttp_test_finish {
	unsigned int				magic;
#define CHTTP_TEST_FINISH_MAGIC			0x0466CDF2

	TAILQ_ENTRY(chttp_test_finish)		entry;

	const char				*name;
	chttp_test_finish_f			*func;
};

struct chttp_test {
	unsigned int				magic;
#define CHTTP_TEST_MAGIC			0xD1C4671E

	struct chttp_test_context		context;

	pthread_t				thread;
	volatile int				stopped;

	enum chttp_test_verbocity		verbocity;

	struct chttp_test_tree			cmd_tree;
	TAILQ_HEAD(, chttp_test_finish)		finish_list;

	char					*cht_file;
	FILE					*fcht;

	char					*line_raw;
	char					*line_buf;
	size_t					line_raw_len;
	size_t					line_buf_len;
	size_t					lines;
	size_t					lines_multi;

	struct chttp_test_cmd			cmd;
	size_t					cmds;

	int					error;
	int					skip;
};

struct chttp_test_md5 {
	unsigned int				magic;
#define CHTTP_TEST_MD5_MAGIC			0x4E4330A7

	int					ready;

	uint32_t				i[2];
	uint32_t				buf[4];
	unsigned char				in[64];
	unsigned char				digest[16];
};

#define CHTTP_TEST_TIMEOUT_SEC			10
#define CHTTP_TEST_JOIN_INTERVAL_MS		25

void chttp_test_register_finish(struct chttp_test_context *ctx, const char *name,
	chttp_test_finish_f *func);
void chttp_test_run_finish(struct chttp_test_context *ctx, const char *name);
void chttp_test_run_all_finish(struct chttp_test *test);

void chttp_test_cmds_init(struct chttp_test *test);
struct chttp_test_cmdentry *chttp_test_cmds_get(struct chttp_test *test, const char *name);

void chttp_test_unescape(struct chttp_test_param *param);
int chttp_test_readline(struct chttp_test *test, size_t append_len);
void chttp_test_parse_cmd(struct chttp_test *test);

struct chttp_test *chttp_test_convert(struct chttp_test_context *ctx);
void chttp_test_skip(struct chttp_test_context *ctx);
void __chttp_attr_printf_p(3) chttp_test_log(struct chttp_test_context *ctx,
	enum chttp_test_verbocity level, const char *fmt, ...);
void __chttp_attr_printf chttp_test_warn(int condition, const char *fmt, ...);
void __chttp_attr_printf chttp_test_ERROR(int condition, const char *fmt, ...);
long chttp_test_parse_long(const char *str);
void chttp_test_ERROR_param_count(struct chttp_test_cmd *cmd, size_t count);
void chttp_test_ERROR_string(const char *str);
void chttp_test_sleep_ms(long ms);
int chttp_test_join_thread(pthread_t thread, volatile int *stopped,
	unsigned long timeout_ms);
size_t chttp_test_line_pos(struct chttp_test *test);
void chttp_test_random_seed(void);
long chttp_test_random(long low, long high);
void chttp_test_fill_random(uint8_t *buf, size_t len);

void chttp_test_md5_init(struct chttp_test_md5 *md5);
void chttp_test_md5_update(struct chttp_test_md5 *md5, uint8_t *input, size_t len);
void chttp_test_md5_final(struct chttp_test_md5 *md5);
void chttp_test_md5_store_server(struct chttp_test_context *ctx, struct chttp_test_md5 *md5);
void chttp_test_md5_store_client(struct chttp_test_context *ctx, struct chttp_test_md5 *md5);

#define chttp_test_ok(test)						\
	do {								\
		assert(test);						\
		assert((test)->magic == CHTTP_TEST_MAGIC);		\
	} while (0)

#endif /* _CHTTP_TEST_H_INCLUDED_ */
