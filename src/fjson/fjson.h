/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifndef _FJSON_H_INCLUDED_
#define _FJSON_H_INCLUDED_

struct fjson_context {
	unsigned int			magic;
#define FJSON_CTX_MAGIC			0x86EC1921

	unsigned int			do_free:1;
};

void fjson_context_init(struct fjson_context *ctx);
void fjson_parse_token(struct fjson_context *ctx, const char *buf);
struct fjson_context *fjson_context_alloc(void);
void fjson_context_free(struct fjson_context *ctx);

#define fjson_context_ok(ctx)						\
	do {								\
		assert(ctx);						\
		assert((ctx)->magic == FJSON_CTX_MAGIC);		\
	} while (0)

#endif /* _FJSON_H_INCLUDED_ */
