/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "fiberfs.h"
#include "fbr_xxhash.h"

int _IS_FIBERFS_TEST;

void
fbr_sleep_ms(double ms)
{
	assert(ms >= 0);

	struct timespec tspec, rem;

	tspec.tv_sec = (time_t)(ms / 1000);
	tspec.tv_nsec = ((time_t)(ms * 1000L * 1000L)) % (1000L * 1000L * 1000L);

	errno = 0;
	while (nanosleep(&tspec, &rem) && errno == EINTR) {
		tspec.tv_sec = rem.tv_sec;
		tspec.tv_nsec = rem.tv_nsec;
		errno = 0;
	}
}

double
fbr_get_time(void)
{
	struct timespec ts;
	assert_zero(clock_gettime(CLOCK_REALTIME, &ts));

	return fbr_convert_timespec(&ts);
}

double
fbr_convert_timespec(struct timespec *ts)
{
	assert(ts);

	double timestamp = (double)ts->tv_sec;
	timestamp += (double)ts->tv_nsec / (1000 * 1000 * 1000);

	return timestamp;
}

void
fbr_timespec_add_clock(struct timespec *ts)
{
	assert(ts);

	struct timespec now;
	assert_zero(clock_gettime(CLOCK_REALTIME, &now));

	long ns = 1000L * 1000L * 1000L;

	ts->tv_nsec += now.tv_nsec;
	assert_dev(ts->tv_nsec / ns <= 1);
	ts->tv_sec += ts->tv_nsec / ns;
	ts->tv_sec += now.tv_sec;
	ts->tv_nsec %= ns;
	assert_dev(ts->tv_nsec < ns);
}

unsigned long
fbr_parse_ulong(const char *str, size_t length)
{
	assert(str);
	assert(length);

	char *end;
	unsigned long ret = strtol(str, &end, 10);

	if ((ret == ULONG_MAX && errno == ERANGE ) || end != str + length) {
		return 0;
	}

	return ret;
}

// This compiles out code if we are a release build
int
fbr_is_dev(void)
{
#ifdef FBR_NO_ASSERT_DEV
	return 0;
#else
	return 1;
#endif
}

// This checks if we are running under a fiber_test context
int
fbr_is_test(void)
{
	if (_IS_FIBERFS_TEST) {
		return 1;
	}

	return 0;
}

fbr_hash_t
fbr_hash(const void *buffer, size_t buffer_len)
{
	XXH64_hash_t hash = XXH3_64bits(buffer, buffer_len);
	static_ASSERT(sizeof(hash) == sizeof(fbr_hash_t));

	return (fbr_hash_t)hash;
}

void
fbr_strcpy(char *dest, size_t dest_len, char *source)
{
	assert(dest);
	assert(dest_len);
	assert(source);

	fbr_snprintf(dest, dest_len, "%s", source);
}

size_t __fbr_attr_printf(3)
fbr_snprintf(char *buffer, size_t size, const char *format, ...)
{
	assert(buffer);
	assert(size);
	assert(format);

	va_list ap;
	va_start(ap, format);

	int ret = vsnprintf(buffer, size, format, ap);
	assert(ret >= 0 && (size_t)ret < size);

	va_end(ap);

	return (size_t)ret;
}

size_t
fbr_bin2hex(const void *input, size_t input_len, char *output, size_t output_len)
{
	assert(input);
	assert(input_len);
	assert(output);
	assert(output_len >= (input_len * 2) + 1);

	output[0] = '\0';
	size_t i = 0;

	for (i = 0; i < input_len; i++) {
		assert_dev((i * 2) + 3 <= output_len);
		int ret = snprintf(&output[i * 2], 3, "%.2x",
			(unsigned char)((const char*)input)[i]);
		assert(ret == 2);
	}

	return (i * 2);
}

static unsigned char
_util_char2int(char c)
{
	if (c >= '0' && c <= '9') {
		return (c - '0');
	} else if (c >= 'a' && c <= 'f') {
		return (c - 87);
	} else if (c >= 'A' && c <= 'F') {
		return (c - 55);
	}

	return 0;
}

static unsigned char
_util_hex2int(const char *hex)
{
	assert(hex);

	unsigned char value = _util_char2int(hex[0]) << 4;
	value += _util_char2int(hex[1]);

	return value;
}

size_t
fbr_hex2bin(const char *input, size_t input_len, void* output, size_t output_len)
{
	assert(input);
	assert(input_len);
	assert(output);
	assert(output_len >= input_len / 2);

	size_t i = 0;
	for (i = 0; i < input_len - 1; i += 2) {
		assert_dev(i / 2 < output_len);
		((char*)output)[i / 2] = _util_hex2int(&input[i]);
	}

	return (i / 2);
}

void
fbr_thread_name(const char *name)
{
	assert(name);
	int ret = pthread_setname_np(pthread_self(), name);
	assert_zero_dev(ret);
}
