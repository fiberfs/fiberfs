# FiberFS Makefile (tests)

FIBERFS_TEST=../src/fiberfs_test
FLAGS=-q
TESTS=$(sort $(wildcard */*.cht */*.tst))
TESTS_JSON=$(sort $(wildcard 003_json/*.tst))
TESTS_FIBER=$(sort $(wildcard 004_fiber/*.tst))
PRE_EXEC=
VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
GDB=gdb --args

.PHONY:	all test check fiberfs_test valgrind verbose json fiber

all:		check

test:		check

$(FIBERFS_TEST):
		$(MAKE) -C .. fiberfs_test

valgrind:
		$(eval PRE_EXEC=$(VALGRIND))
		@echo valgrind enabled

verbose:
		$(eval FLAGS=-vv)
		@echo verbose enabled

check:		$(TESTS)

json:		$(TESTS_JSON)

fiber:		$(TESTS_FIBER)

FORCE:

%.cht:		$(FIBERFS_TEST) FORCE
		$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@

%.tst:		$(FIBERFS_TEST) FORCE
		$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@
