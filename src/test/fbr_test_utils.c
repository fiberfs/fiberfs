/*
 * Copyright (c) 2024 FiberFS
 *
 */

#include "test/fbr_test.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>

struct fbr_test *
fbr_test_convert(struct fbr_test_context *ctx)
{
	struct fbr_test *test;

	fbr_test_context_ok(ctx);

	test = ctx->test;
	fbr_test_ok(test);

	return test;
}

void __fbr_attr_printf_p(3)
fbr_test_log(struct fbr_test_context *ctx, enum fbr_test_verbocity level,
    const char *fmt, ...)
{
	struct fbr_test *test;
	va_list ap;

	if (ctx) {
		fbr_test_context_ok(ctx);
		test = fbr_test_convert(ctx);

		if (level != FBR_LOG_FORCE && (test->verbocity == FBR_LOG_NONE ||
		    test->verbocity < level)) {
			return;
		}
	} else {
		assert(level == FBR_LOG_FORCE);
	}

	if (level == FBR_LOG_NONE) {
		printf("- ");
	} else if (level == FBR_LOG_VERBOSE) {
		printf("-- ");
	} else if (level == FBR_LOG_VERY_VERBOSE) {
		printf("--- ");
	}

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");
}

void
fbr_test_skip(struct fbr_test_context *ctx)
{
	struct fbr_test *test;

	fbr_test_context_ok(ctx);
	test = fbr_test_convert(ctx);

	test->skip = 1;
}

void __fbr_attr_printf
fbr_test_warn(int condition, const char *fmt, ...)
{
	va_list ap;

	if (!condition) {
		return;
	}

	printf("WARNING: ");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\n");
}

void __fbr_attr_printf
fbr_test_ERROR(int condition, const char *fmt, ...)
{
	va_list ap;

	if (!condition) {
		return;
	}

	printf("ERROR: ");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	printf("\nFAILED\n");

	exit(1);
}

long
fbr_test_parse_long(const char *str)
{
	long ret;
	char *end;

	assert(str);

	errno = 0;

	ret = strtol(str, &end, 10);

	if (ret == LONG_MAX || ret == LONG_MIN || errno || end == str || *end != '\0') {
		fbr_test_ERROR(1, "invalid number '%s'", str);
	}

	return ret;
}

void
fbr_test_ERROR_param_count(struct fbr_test_cmd *cmd, size_t count)
{
	size_t i;

	fbr_test_cmd_ok(cmd);
	fbr_test_ERROR_string(cmd->name);
	fbr_test_ERROR(cmd->param_count != count,
		"invalid parameter count, found %zu, expected %zu", cmd->param_count, count);

	for (i = 0; i < cmd->param_count; i++) {
		fbr_test_ERROR(cmd->params[i].len == 0, "empty parameter found");
		// TODO remove
		assert(cmd->params[i].len == strlen(cmd->params[i].value));
	}
}

void
fbr_test_ERROR_string(const char *str)
{
	fbr_test_ERROR(!str || !*str, "invalid string");
}

void
fbr_test_sleep_ms(long ms)
{
	struct timespec tspec, rem;

	assert(ms >= 0);

	tspec.tv_sec = ms / 1000;
	tspec.tv_nsec = (ms % 1000) * 1000 * 1000;

	errno = 0;
	while (nanosleep(&tspec, &rem) && errno == EINTR) {
		tspec.tv_sec = rem.tv_sec;
		tspec.tv_nsec = rem.tv_nsec;
		errno = 0;
	}
}

int
fbr_test_join_thread(pthread_t thread, volatile int *stopped, unsigned long *timeout_ms)
{
	unsigned long time;

	assert(stopped);
	assert(timeout_ms);

	time = 0;

	while (!*stopped) {
		fbr_test_sleep_ms(FBR_TEST_JOIN_INTERVAL_MS);

		time += FBR_TEST_JOIN_INTERVAL_MS;

		if (*timeout_ms && time > *timeout_ms) {
			return 1;
		}
	}

	assert_zero(pthread_join(thread, NULL));

	return 0;
}

size_t
fbr_test_line_pos(struct fbr_test *test)
{
	fbr_test_ok(test);

	return (test->lines - test->lines_multi);
}

void
fbr_test_random_seed(void)
{
	struct timespec now;

	assert_zero(clock_gettime(CLOCK_MONOTONIC, &now));
	srandom(now.tv_sec + now.tv_nsec);
}

// Inclusive
long
fbr_test_gen_random(long low, long high)
{
	long rval;

	assert(low >= 0);
	assert(high >= low);

	rval = random();
	rval %= (high - low) + 1;
	rval += low;

	return rval;
}

void
fbr_test_fill_random(uint8_t *buf, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		// TODO write a wider char if possible
		buf[i] = fbr_test_gen_random(0, UINT8_MAX);
	}
}
