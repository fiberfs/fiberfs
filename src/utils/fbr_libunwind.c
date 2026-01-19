/*
 * Copyright (c) 2024-2026 FiberFS LLC
 * All rights reserved.
 *
 */

#ifdef FBR_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#endif

#include <stdio.h>
#include <string.h>

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
fbr_libunwind_backtrace(char **stack_syms, int len)
{
#ifdef FBR_LIBUNWIND
	fprintf(stderr, "\nStack symbols:\n");

	unw_context_t context;
	unw_cursor_t cursor;

	unw_getcontext(&context);
	unw_init_local(&cursor, &context);

	int i = 0;

	while (unw_step(&cursor) > 0) {
		char symbol[256];
		unw_word_t offset;

		int ret = unw_get_proc_name(&cursor, symbol, sizeof(symbol), &offset);

		if (!ret) {
			fprintf(stderr, "  %s() [0x%lx]\n", symbol, (long)offset);
		} else {
			fprintf(stderr, "  [unknown]\n");
		}

		if (i < len && strncmp(stack_syms[i], "/lib", 4)) {
			for (size_t j = 0; stack_syms[i][j]; j++) {
				if (stack_syms[i][j] == '(') {
					stack_syms[i][j] = ' ';
				} else if (stack_syms[i][j] == ')') {
					stack_syms[i][j] = '\0';
					break;
				}
			}

			fprintf(stderr, "    addr2line -spfe %s\n", stack_syms[i]);
		}

		i++;
	}
#else
	(void)stack_syms;
	(void)len;
#endif
}
