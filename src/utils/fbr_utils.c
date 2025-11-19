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
#include <string.h>
#include <time.h>

#include "fiberfs.h"
#include "fbr_xxhash.h"
#include "cstore/fbr_cstore_path.h"

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

void
fbr_sleep_backoff(unsigned int attempts)
{
	if (!attempts) {
		return;
	}

	unsigned int delay_ms = attempts * 200;
	if (delay_ms > 3000) {
		delay_ms = 3000;
	}

	delay_ms += random() % 100;

	fbr_sleep_ms(delay_ms);
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

size_t
fbr_strcpy(char *dest, size_t dest_len, const char *source)
{
	assert(dest);
	assert(dest_len);
	assert(source);

	size_t ret = fbr_snprintf(dest, dest_len, "%s", source);

	return ret;
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

static inline void
_util_char2hex(unsigned char c, char *output, int upper)
{
	assert_dev(output);

	static const char *hex_UPPER = "0123456789ABCDEF";
	static const char *hex_lower = "0123456789abcdef";

	if (upper) {
		output[0] = hex_UPPER[(c >> 4) & 0x0F];
		output[1] = hex_UPPER[c & 0x0F];
		return;
	}

	output[0] = hex_lower[(c >> 4) & 0x0F];
	output[1] = hex_lower[c & 0x0F];
}

size_t
fbr_bin2hex(const void *input, size_t input_len, char *output, size_t output_len)
{
	assert(input);
	assert(input_len);
	assert(output);
	assert(output_len >= FBR_HEX_LEN(input_len));

	size_t i;
	for (i = 0; i < input_len; i++) {
		assert_dev((i * 2) + 3 <= output_len);
		unsigned char c = (unsigned char)((const char*)input)[i];
		_util_char2hex(c, &output[i * 2], 0);
	}

	output[i * 2] = '\0';

	return (i * 2);
}

static inline unsigned char
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

static inline unsigned char
_util_hex2int(const char *hex)
{
	assert_dev(hex);

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

size_t
fbr_urlencode(const char *input, size_t input_len, char *output, size_t output_len)
{
	assert(input);
	assert(input_len);
	assert(output);
	assert(output_len > input_len * 3);

	size_t len = 0;

	for (size_t i = 0; i < input_len; i++, len++) {
		unsigned char c = (unsigned char)input[i];
		if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			output[len] = c;
			continue;
		}

		switch (c) {
			case '.':
			case '-':
			case '_':
			case '~':
			case '/':
				output[len] = c;
				continue;
			default:
				output[len] = '%';
				_util_char2hex(c, &output[len + 1], 1);
				len += 2;
				continue;
		}
	}

	assert(len < output_len);
	output[len] = '\0';

	return len;
}

void
fbr_thread_name(const char *name)
{
	assert(name);
	int ret = pthread_setname_np(pthread_self(), name);
	assert_zero_dev(ret);
}

int
fbr_check_name(const char *name)
{
	assert(name);

	size_t name_len = strlen(name);
	if (!name_len || name_len >= PATH_MAX) {
		return EINVAL;
	}

	if (strcasestr(name, FBR_FIBERFS_NAME)) {
		return EINVAL;
	}

	return 0;
}
