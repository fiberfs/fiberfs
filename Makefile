# FiberFS Makefile

.PHONY:	all test check valgrind

all:
		$(MAKE) -C src $@

test check:
		$(MAKE) -C tests $@

valgrind:
		$(MAKE) -C tests $@ all

%:
		$(MAKE) -C src $@
