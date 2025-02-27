/*
 * Copyright (c) 2024-2025 FiberFS
 * All rights reserved.
 *
 */

#ifndef _FBR_ID_H_INCLUDED_
#define _FBR_ID_H_INCLUDED_

#define FBR_ID_TIMEBITS				(sizeof(fbr_id_part_t) * 8)
#define FBR_ID_RANDBITS				31 // RAND_MAX
#define FBR_ID_ALLBITS				(FBR_ID_TIMEBITS + FBR_ID_RANDBITS)
#define FBR_ID_OTHERBITS			(sizeof(fbr_id_t) * 8 - FBR_ID_ALLBITS)
#define FBR_ID_FULLRANDBITS			(FBR_ID_RANDBITS + FBR_ID_OTHERBITS)
#define FBR_ID_TIMEBITS_MAX			((1L << FBR_ID_TIMEBITS) - 1)
#define FBR_ID_RANDBITS_MAX			((1L << FBR_ID_RANDBITS) - 1)
#define FBR_ID_OTHERBITS_MAX			((1L << FBR_ID_OTHERBITS) - 1)
#define FBR_ID_STRING_MAX			(21 + 1)

typedef unsigned long fbr_id_t;
typedef unsigned int fbr_id_part_t;

struct fbr_id_parts {
	union {
		fbr_id_part_t			full_random:FBR_ID_FULLRANDBITS;
		struct {
			fbr_id_part_t		other:FBR_ID_OTHERBITS;
			fbr_id_part_t		random:FBR_ID_RANDBITS;
		} random_parts;
	};
	fbr_id_part_t				timestamp:FBR_ID_TIMEBITS;
};

struct fbr_id {
	union {
		fbr_id_t			value;
		struct fbr_id_parts		parts;
	};
};

#endif /* _FBR_ID_H_INCLUDED_ */
