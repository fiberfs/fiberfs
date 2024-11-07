# FiberFS Makefile (tests)

FIBERFS_TEST=../src/fiberfs_test
FLAGS=-vv
CHTS=$(sort $(wildcard */*.cht */*.tst))
VALGRIND=
GDB=gdb --args

.PHONY:	all test check fiberfs_test valgrind verbose

all:		check

FORCE:

fiberfs_test:
		$(MAKE) -C .. fiberfs_test

valgrind:	VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
valgrind:	check

test:		check

check:		FLAGS=-q
check:		$(CHTS)

verbose:	$(CHTS)

%.cht:		fiberfs_test FORCE
		$(VALGRIND) $(FIBERFS_TEST) $(FLAGS) $@

%.tst:		fiberfs_test FORCE
		$(VALGRIND) $(FIBERFS_TEST) $(FLAGS) $@
