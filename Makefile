# FiberFS Makefile

.PHONY:	all test check tests valgrind

all:
		$(MAKE) -C src $@

test:		check

check:
		$(MAKE) -C tests $@

valgrind:
		$(MAKE) -C tests $@

%:
		$(MAKE) -C src $@
