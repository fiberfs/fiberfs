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

#define FBR_PATH_MAX				PATH_MAX
#define FBR_HASH_SLEN				((sizeof(fbr_hash_t) * 2) + 1)

typedef uint64_t fbr_hash_t;

void fbr_sleep_ms(double ms);
double fbr_get_time(void);
double fbr_convert_timespec(struct timespec *ts);
void fbr_timespec_add_clock(struct timespec *ts);
unsigned long fbr_parse_ulong(const char *str, size_t length);
int fbr_is_dev(void);
int fbr_is_test(void);
fbr_hash_t fbr_hash(const void *buffer, size_t buffer_len);
void fbr_strcpy(char *dest, size_t dest_len, char *source);
size_t fbr_bin2hex(const void *input, size_t input_len, char *output, size_t output_len);
size_t fbr_hex2bin(const char *input, size_t input_len, void* output, size_t output_len);

#define _FBR_STRINGIFY(_value)			#_value
#define FBR_STRINGIFY(value)			_FBR_STRINGIFY(value)

#define fbr_atomic_add(dest_ptr, value)					\
	__sync_add_and_fetch(dest_ptr, value);
#define fbr_atomic_sub(dest_ptr, value)					\
	__sync_sub_and_fetch(dest_ptr, value);
#define fbr_compare_swap(dest_ptr, old_value, new_value)		\
	__sync_val_compare_and_swap(dest_ptr, old_value, new_value)
#define fbr_memory_sync()						\
	__sync_synchronize()

#define fbr_ZERO(p)							\
	explicit_bzero(p, sizeof(*(p)))

#define fbr_array_len(array)						\
	(sizeof(array) / sizeof(*(array)))

#endif /* _FBR_UTILS_H_INCLUDED_ */
