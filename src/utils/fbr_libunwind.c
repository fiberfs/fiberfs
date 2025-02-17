/*
 * Copyright (c) 2024 FiberFS
 *
 */

#ifdef FBR_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

#include <stdio.h>

int
fbr_libunwind_enabled(void)
{
#ifdef FBR_LIBUNWIND
	return 1;
#else
	return 0;
#endif
}

void
fbr_libunwind_backtrace(void)
{
#ifdef FBR_LIBUNWIND
	fprintf(stderr, "\nStack symbols:\n");

	unw_context_t context;
	unw_cursor_t cursor;

	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	while (unw_step(&cursor) > 0) {
		char symbol[256];
		unw_word_t offset;

		int ret = unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offset);

		if (!ret) {
			fprintf(stderr, "  %s() [0x%lx]\n", symbol, (long)offset);
		} else {
			fprintf(stderr, "  [unknown]\n");
		}
	}
#endif
}
