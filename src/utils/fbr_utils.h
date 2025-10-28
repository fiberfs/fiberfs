/*
 * Copyright (c) 2024 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_UTILS_H_INCLUDED_
#define _FBR_UTILS_H_INCLUDED_

#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define FBR_PATH_MAX				(PATH_MAX + 128)
#define FBR_HASH_SLEN				((sizeof(fbr_hash_t) * 2) + 1)

typedef uint64_t fbr_hash_t;

void fbr_sleep_ms(double ms);
double fbr_get_time(void);
double fbr_convert_timespec(struct timespec *ts);
void fbr_timespec_add_clock(struct timespec *ts);
void fbr_sleep_backoff(unsigned int attempts);
unsigned long fbr_parse_ulong(const char *str, size_t length);
int fbr_is_dev(void);
int fbr_is_test(void);
fbr_hash_t fbr_hash(const void *buffer, size_t buffer_len);
void fbr_strcpy(char *dest, size_t dest_len, const char *source);
size_t __fbr_attr_printf(3) fbr_snprintf(char *buffer, size_t size, const char *format, ...);
size_t fbr_bin2hex(const void *input, size_t input_len, char *output, size_t output_len);
size_t fbr_hex2bin(const char *input, size_t input_len, void* output, size_t output_len);
void fbr_thread_name(const char *name);
int fbr_check_name(const char *name);

#define _FBR_STRINGIFY(_value)			#_value
#define FBR_STRINGIFY(value)			_FBR_STRINGIFY(value)

#define fbr_strbcpy(dest, source)					\
	fbr_strcpy(dest, sizeof(dest), source)
#define fbr_bprintf(buf, fmt, ...)					\
	fbr_snprintf(buf, sizeof(buf), fmt, ##__VA_ARGS__)
#define fbr_atomic_add(dest_ptr, value)					\
	__sync_add_and_fetch(dest_ptr, value);
#define fbr_atomic_sub(dest_ptr, value)					\
	__sync_sub_and_fetch(dest_ptr, value);
#define fbr_compare_swap(dest_ptr, old_value, new_value)		\
	__sync_val_compare_and_swap(dest_ptr, old_value, new_value)
#define fbr_memory_sync()						\
	__sync_synchronize()
#define fbr_zero(ptr)							\
	explicit_bzero(ptr, sizeof(*(ptr)))
#define fbr_array_len(array)						\
	(sizeof(array) / sizeof(*(array)))

#endif /* _FBR_UTILS_H_INCLUDED_ */
