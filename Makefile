# FiberFS Makefile

.PHONY:	all test check valgrind FORCE

all:
		$(MAKE) -C src $@

test check:
		$(MAKE) -C tests $@

valgrind:
		$(MAKE) -C tests $@ all

FORCE:

%:		FORCE
		$(MAKE) -C src $@
