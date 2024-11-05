# FiberFS Makefile (tests)

CHTTP_TEST=../src/chttp_test
V=vv
CHTS=$(sort $(wildcard */*.cht */*.tst))
VALGRIND=
GDB=gdb --args

.PHONY:	all test check chttp_test valgrind verbose

all:		check

FORCE:

chttp_test:
		$(MAKE) -C .. chttp_test

valgrind:	VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
valgrind:	check

test:		check

check:		V=q
check:		$(CHTS)

verbose:	$(CHTS)

%.cht:		chttp_test FORCE
		$(VALGRIND) $(CHTTP_TEST) -$(V) $@

%.tst:		chttp_test FORCE
		$(VALGRIND) $(CHTTP_TEST) -$(V) $@

