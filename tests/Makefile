# FiberFS Makefile (tests)

FIBERFS_TEST=../src/fiberfs_test
FLAGS=-q
TESTS=$(sort $(wildcard */*.cht */*.tst))
TESTS_JSON=$(sort $(wildcard 003_json/*.tst))
TESTS_FIBER=$(sort $(wildcard 004_fiber/*.tst))
TESTS_FIBERX=$(sort $(wildcard 004_fiber/*.tstx))
PRE_EXEC=
VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
GDB=gdb --args

export FIBER_VALGRIND=$(PRE_EXEC)
export FIBER_FLAGS=$(FLAGS)

.PHONY: all test check FORCE valgrind verbose sudo json fiber fiberx

all:			check

test:			check

FORCE:

$(FIBERFS_TEST):	FORCE
			$(MAKE) -C .. fiberfs_test

valgrind:
			$(eval PRE_EXEC=$(VALGRIND))
			@echo valgrind: enabled

verbose:
			$(eval FLAGS=-vv)
			@echo verbose: enabled

sudo:
			sudo true

check:			$(TESTS)

json:			$(TESTS_JSON)

fiber:			$(TESTS_FIBER)

fiberx:			$(TESTS_FIBERX)

%.cht %.tst %.tstm:	$(FIBERFS_TEST) FORCE
			$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@

%tstx:			$(FIBERFS_TEST) FORCE | sudo
			$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@
