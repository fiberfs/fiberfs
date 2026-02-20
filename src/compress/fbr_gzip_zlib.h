/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_ZLIB_H_INCLUDED_
#define _FBR_ZLIB_H_INCLUDED_

#ifdef FBR_ZLIB

#define ZLIB_CONST

#include <stddef.h>
#include <zlib.h>

#include "fiberfs.h"

#define FBR_ZLIB_WINDOW_BITS		(15 + 16)
#define FBR_ZLIB_DEFLATE_LEVEL		6
#define FBR_ZLIB_DEFLATE_MEM		8

enum fbr_zlib_type {
	FBR_ZLIB_NONE = 0,
	FBR_ZLIB_INFLATE,
	FBR_ZLIB_DEFLATE
};

struct fbr_zlib {
	unsigned int			magic;
#define FBR_ZLIB_MAGIC			0xAE59CB8C

	enum fbr_zlib_type		type;
	int				status;
	int				zstate;

	fbr_bitflag_t			do_free:1;

	unsigned char			*buffer;
	size_t				buffer_len;

	z_stream			zs;
};

void fbr_zlib_inflate_init(struct fbr_zlib *zlib);
void fbr_zlib_deflate_init(struct fbr_zlib *zlib);
struct fbr_zlib *fbr_zlib_alloc(enum fbr_zlib_type type);
int fbr_zlib_flate(struct fbr_zlib *zlib, const unsigned char *input, size_t input_len,
	unsigned char *output, size_t output_len, size_t *written, int finish_deflate);
void fbr_zlib_free(struct fbr_zlib *zlib);

#define fbr_zlib_ok(zlib)	\
	fbr_magic_check(zlib, FBR_ZLIB_MAGIC)

#endif /* FBR_ZLIB */

#endif /* _FBR_ZLIB_H_INCLUDED_ */
