/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_TEST_H_INCLUDED_
#define _FBR_TEST_H_INCLUDED_

#include "fiberfs.h"
#include "data/queue.h"
#include "data/tree.h"

#include <stdint.h>
#include <stdio.h>
#include <pthread.h>

enum fbr_test_verbocity {
	FBR_LOG_FORCE = 0,
	FBR_LOG_NONE,
	FBR_LOG_VERBOSE,
	FBR_LOG_VERY_VERBOSE
};

#define FBR_TEST_MAX_PARAMS			16

struct fbr_test;
struct fbr_test_sys;
struct fbr_test_fuse;
struct fbr_test_log_printer;
struct fbr_test_random;
struct fbr_test_var;
struct chttp_test_context;

struct fbr_test_context {
	unsigned int				magic;
#define FBR_TEST_CONTEXT_MAGIC			0xAD98A6FF

	struct fbr_test				*test;
	struct fbr_test_sys			*sys;
	struct fbr_test_fuse			*test_fuse;
	struct fbr_test_log_printer		*printer;
	struct fbr_test_random			*random;
	struct fbr_test_var			*var;
	struct fbr_test_shell			*shell;
	struct chttp_test_context		*chttp_test;
	struct fbr_test_cstore			*cstore;
};

struct fbr_test_param {
	char					*value;
	size_t					len;

	char					*variable;

	unsigned int				v_const:1;
};

struct fbr_test_cmd;

typedef void (fbr_test_cmd_f)(struct fbr_test_context *, struct fbr_test_cmd *);
typedef char* (fbr_test_var_f)(struct fbr_test_context *);

struct fbr_test_cmd {
	unsigned int				magic;
#define FBR_TEST_CMD_MAGIC			0x8F923F2E

	const char				*name;

	size_t					param_count;
	struct fbr_test_param			params[FBR_TEST_MAX_PARAMS];

	fbr_test_cmd_f				*func;

	unsigned int				async:1;
};

struct fbr_test_cmdentry {
	unsigned int				magic;
#define FBR_TEST_ENTRY_MAGIC			0x52C66713

	RB_ENTRY(fbr_test_cmdentry)		entry;

	const char				*name;
	fbr_test_cmd_f				*cmd_func;
	fbr_test_var_f				*var_func;

	unsigned int				is_cmd:1;
	unsigned int				is_var:1;
};

RB_HEAD(fbr_test_tree, fbr_test_cmdentry);

typedef void (fbr_test_finish_f)(struct fbr_test_context*);

struct fbr_test_finish {
	unsigned int				magic;
#define FBR_TEST_FINISH_MAGIC			0x0466CDF2

	TAILQ_ENTRY(fbr_test_finish)		entry;

	const char				*name;
	fbr_test_finish_f			*func;
};

struct fbr_test {
	unsigned int				magic;
#define FBR_TEST_MAGIC				0xD1C4671E

	struct fbr_test_context			*context;

	pthread_t				thread;
	volatile int				stopped;
	volatile unsigned long			timeout_ms;

	enum fbr_test_verbocity			verbocity;

	struct fbr_test_cmdentry		*cmds;
	size_t					cmds_size;
	size_t					cmds_pos;
	struct fbr_test_tree			cmd_tree;
	TAILQ_HEAD(, fbr_test_finish)		finish_list;

	const char				*prog_name;
	char					*test_file;
	FILE					*ft_file;

	char					*line_raw;
	char					*line_buf;
	size_t					line_raw_len;
	size_t					line_buf_len;
	size_t					lines;
	size_t					lines_multi;

	struct fbr_test_cmd			cmd;
	size_t					cmd_count;

	int					forked;
	int					error;
	int					skip;
};

#define FBR_TEST_DEFAULT_TIMEOUT_SEC		10
#define FBR_TEST_JOIN_INTERVAL_MS		25

int fbr_test_main(int argc, char **argv);
void fbr_test_register_finish(struct fbr_test_context *ctx, const char *name,
	fbr_test_finish_f *func);
void fbr_test_run_all_finish(struct fbr_test *test);
void fbr_test_cleanup(void);
void fbr_test_context_abort(void);
int fbr_test_is_forked(void);
int fbr_test_is_thread(void);
void fbr_test_force_error(void);
void fbr_finish_ERROR(int cond, const char *msg);
struct fbr_test_context *fbr_test_get_ctx(void);

void fbr_test_cmds_init(struct fbr_test *test);
struct fbr_test_cmdentry *fbr_test_cmds_get(struct fbr_test *test, const char *name);

void fbr_test_unescape(struct fbr_test_param *param);
int fbr_test_readline(struct fbr_test *test, size_t append_len);
char *fbr_test_read_var(struct fbr_test *test, const char *variable);
void fbr_test_parse_cmd(struct fbr_test *test);

void fbr_test_fork(struct fbr_test_context *ctx, struct fbr_test_cmd *cmd);
int fbr_test_can_fork(struct fbr_test_context *ctx);
int fbr_test_can_vfork(struct fbr_test_context *ctx);

char *fbr_test_mkdir_tmp(struct fbr_test_context *ctx, char *tmproot);

struct fbr_test *fbr_test_convert(struct fbr_test_context *ctx);
void fbr_test_skip(struct fbr_test_context *ctx);
int fbr_test_can_log(struct fbr_test *test, enum fbr_test_verbocity level);
void fbr_test_vlog(struct fbr_test_context *ctx, enum fbr_test_verbocity level,
	int newline, const char *fmt, va_list ap);
void __fbr_attr_printf(1) fbr_test_logs(const char *fmt, ...);
void __fbr_attr_printf(1) fbr_test_logs_nl(const char *fmt, ...);
void __fbr_attr_printf(3) fbr_test_log(struct fbr_test_context *ctx,
	enum fbr_test_verbocity level, const char *fmt, ...);
void __fbr_attr_printf(2) fbr_test_warn(int condition, const char *fmt, ...);
void __fbr_attr_printf(5) __fbr_noreturn fbr_test_do_abort(const char *assertion,
	const char *function, const char *file, int line, const char *fmt, ...);
long fbr_test_parse_long(const char *str);
void fbr_test_ERROR_param_count(struct fbr_test_cmd *cmd, size_t count);
void fbr_test_ERROR_string(const char *str);
void fbr_test_sleep_ms(long ms);
int fbr_test_join_thread(pthread_t thread, volatile int *stopped,
	volatile unsigned long *timeout_ms);
size_t fbr_test_line_pos(struct fbr_test *test);
void fbr_test_random_seed(void);
long fbr_test_gen_random(long low, long high);
void fbr_test_fill_random(uint8_t *buf, size_t len);
int fbr_test_is_valgrind(void);

#define fbr_test_ok(test)		fbr_magic_check(test, FBR_TEST_MAGIC)
#define fbr_test_context_ok(context)	fbr_magic_check(context, FBR_TEST_CONTEXT_MAGIC)
#define fbr_test_cmd_ok(cmd)		fbr_magic_check(cmd, FBR_TEST_CMD_MAGIC)

#define fbr_test_ERROR(cond, fmt, ...)					\
{									\
	if (__builtin_expect(cond, 0)) {				\
		fbr_test_do_abort(#cond, __func__, __FILE__, __LINE__,	\
			fmt, ##__VA_ARGS__);				\
	}								\
}
#define fbr_test_ASSERT(cond, fmt, ...)					\
	fbr_test_ERROR(!(cond), fmt, ##__VA_ARGS__);
#define fbr_test_ABORT(fmt, ...)					\
	fbr_test_do_abort(NULL, __func__, __FILE__, __LINE__, fmt,	\
		##__VA_ARGS__);

#endif /* _FBR_TEST_H_INCLUDED_ */
