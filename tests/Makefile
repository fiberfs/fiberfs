# FiberFS Makefile (tests)

FIBERFS_TEST=../src/fiberfs_test
FLAGS=-q
TESTS=$(sort $(wildcard */*.cht */*.tst))
TESTS_JSON=$(sort $(wildcard 003_json/*.tst))
TESTS_FIBER=$(sort $(wildcard 004_fiber/*.tst))
PRE_EXEC=
VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
GDB=gdb --args

.PHONY:	all test check fiberfs_test valgrind verbose vjson json vfiber fiber

all:		check

FORCE:

fiberfs_test:
		$(MAKE) -C .. fiberfs_test

valgrind:	PRE_EXEC=$(VALGRIND)
valgrind:	check

test:		check

check:		$(TESTS)

verbose:
		$(eval FLAGS=-vv)

vjson:		PRE_EXEC=$(VALGRIND)
vjson:		json

json:		$(TESTS_JSON)

vfiber:		PRE_EXEC=$(VALGRIND)
vfiber:		fiber

fiber:		$(TESTS_FIBER)

%.cht:		fiberfs_test FORCE
		$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@

%.tst:		fiberfs_test FORCE
		$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@
