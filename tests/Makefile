# FiberFS Makefile (tests)

FIBERFS_TEST=../src/fiberfs_test
FLAGS=-q
TESTS=$(sort $(wildcard */*.cht */*.tst))
TESTS_CHTTP=$(sort $(wildcard 001_http/*.cht 002_http_live/*.cht))
TESTS_JSON=$(sort $(wildcard 003_json/*.tst))
TESTS_CORE=$(sort $(wildcard 004_core/*.tst 006_store/*.tst 007_other/*.tst))
TESTS_COREX=$(sort $(wildcard 004_core/*.tstx))
TESTS_ERROR=$(sort $(wildcard */*.tstf))
PRE_EXEC=
VALGRIND=valgrind --error-exitcode=1 --leak-check=full -q
FAIL_CMD=timeout 2 bash -c
FAIL_OUT=>/dev/null 2>&1
GDB=gdb --args

export FIBER_VALGRIND=$(PRE_EXEC)
export FIBER_FLAGS=$(FLAGS)

FIBERFS_TEST_RULE=$(FIBERFS_TEST)
FAST_VAR=FAST
ifdef $(FAST_VAR)
	FIBERFS_TEST_RULE=
endif

.PHONY: all test check FORCE valgrind verbose sudo json core corex error chttp

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
			$(eval FAIL_OUT=)
			@echo verbose: enabled

sudo:
			sudo true

check:			$(TESTS)

chttp:			$(TESTS_CHTTP)

json:			$(TESTS_JSON)

core:			$(TESTS_CORE)

corex:			$(TESTS_COREX)

error:			$(TESTS_ERROR)

%.cht %.tst:		$(FIBERFS_TEST_RULE) FORCE
			$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@

%tstx:			$(FIBERFS_TEST_RULE) FORCE | sudo
			$(PRE_EXEC) $(FIBERFS_TEST) $(FLAGS) $@

%.tstf:			$(FIBERFS_TEST_RULE) FORCE
			$(FAIL_CMD) '$(FIBERFS_TEST) $(FLAGS) $@ $(FAIL_OUT) || echo SUCCESS'
