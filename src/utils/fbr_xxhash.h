/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifndef _FBR_XXHASH_H_INCLUDED_
#define _FBR_XXHASH_H_INCLUDED_

#define XXH_STATIC_LINKING_ONLY

// TODO VSCode Intellisense doesn't like these flags...
#ifndef FBR_IDE_INTELLISENSE
#define XXH_PRIVATE_API
#define XXH_INLINE_ALL
#endif

#include "data/xxhash.h"

typedef XXH3_state_t fbr_xxhash_t;

void fbr_xxhash(fbr_xxhash_t *hash, const void *buffer, size_t buffer_len);
void fbr_xxhash_update(fbr_xxhash_t *hash, const void *buffer, size_t buffer_len);
fbr_hash_t fbr_xxhash_result(fbr_xxhash_t *hash);

#endif /* _FBR_XXHASH_H_INCLUDED_ */
