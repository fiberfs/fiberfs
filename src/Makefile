# FiberFS Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -g -fPIC -I. -Ichttp -Ifjson -fno-omit-frame-pointer
CFLAGS_GCC=
CFLAGS_CLANG=-Wno-gnu-zero-variadic-macro-arguments
CFLAGS_BUILD=
DEPFLAGS=-MMD -MP
LDFLAGS=-shared
LIBFLAGS=
LIBFLAGS_TEST=-lpthread $(LIBFLAGS)
BUILD=build

TEST_SRC:=$(wildcard test/*.c test/*/*.c chttp/test/*.c fjson/test/*.c core/*/test/*.c)
TEST_OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(TEST_SRC)))

CHTTP_CLIENT:=$(wildcard chttp/client/*.c)
CHTTP_CLIENT_OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(CHTTP_CLIENT)))
CHTTP_SRC:=$(wildcard chttp/*.c chttp/*/*.c)
CHTTP_SRC:=$(filter-out $(TEST_SRC) $(CHTTP_CLIENT), $(CHTTP_SRC))
CHTTP_OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(CHTTP_SRC)))

FJSON_CLIENT:=$(wildcard fjson/client/*.c)
FJSON_CLIENT_OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(FJSON_CLIENT)))
FJSON_SRC:=$(wildcard fjson/*.c)
FJSON_OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(FJSON_SRC)))

UTILS_SRC=$(wildcard utils/*.c)
UTILS_OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(UTILS_SRC)))

ALL_SOURCE:=$(shell find * -type f -name '*.c')
SOURCE:=$(filter-out $(TEST_SRC) $(CHTTP_CLIENT) $(CHTTP_SRC) $(FJSON_CLIENT) $(FJSON_SRC), \
	$(ALL_SOURCE))
OBJS:=$(patsubst %,$(BUILD)/%.o,$(basename $(SOURCE)))
DEPS:=$(patsubst %,$(BUILD)/%.d,$(basename $(ALL_SOURCE)))
BUILD_DIRS=$(sort $(dir $(DEPS)))

RM=rm -f
RMDIR=rm -rf
PKG=pkg-config
NULL=/dev/null
TEST_TRUE= > $(NULL) 2>&1 && echo true
TCC=$(CC) -x c - -o $(NULL)

# Validate compiler (CC)
CC_TEST_C='int main() {}'
CC_OK=$(shell printf $(CC_TEST_C) | $(TCC) $(TEST_TRUE))
ifneq ($(CC_OK),true)
$(error CC=$(CC) compiler error, cannot compile)
endif

# Detect fuse3 (required)
FUSE3_PKG=fuse3
define FUSE3_C=
	#define FUSE_USE_VERSION 35 \n
	#include <fuse3/fuse_lowlevel.h> \n
	int main() {
		fuse_lowlevel_version();
	}
endef
FUSE3_CFLAGS=-DFBR_FUSE3
FUSE3_LIB=-lfuse3
FUSE3=$(shell printf "$(FUSE3_C)" | $(TCC) $(FUSE3_LIB) $(TEST_TRUE))
ifeq ($(FUSE3),true)
	CFLAGS_BUILD+=$(FUSE3_CFLAGS)
	LIBFLAGS+=$(FUSE3_LIB)
else
$(error fuse3 not found. Required for compiling)
endif

# Detect openssl (OPENSSL=false to disable)
OPENSSL_PKG=openssl
OPENSSL_C='\#include <openssl/ssl.h>\n int main() {SSL *ssl;}'
OPENSSL_CFLAGS=-DCHTTP_OPENSSL
OPENSSL_LIB=-lssl -lcrypto
OPENSSL=$(shell printf $(OPENSSL_C) | $(TCC) $(OPENSSL_LIB) $(TEST_TRUE))
ifeq ($(OPENSSL),true)
	CFLAGS_BUILD+=$(OPENSSL_CFLAGS)
	LIBFLAGS+=$(OPENSSL_LIB)
endif

# Detect zlib (ZLIB=false to disable)
ZLIB_PKG=zlib
ZLIB_C='\#include <zlib.h>\n int main() {zlibVersion();}'
ZLIB_CFLAGS=-DCHTTP_ZLIB
ZLIB_LIB=-lz
ZLIB=$(shell printf $(ZLIB_C) | $(TCC) $(ZLIB_LIB) $(TEST_TRUE))
ifeq ($(ZLIB),true)
	CFLAGS_BUILD+=$(ZLIB_CFLAGS)
	LIBFLAGS+=$(ZLIB_LIB)
endif

# Detect libunwind (LIBUNWIND=false to disable)
LIBUNWIND_PKG=libunwind
LIBUNWIND_C='\#include <libunwind.h>\n int main() {unw_context_t uc;}'
LIBUNWIND_CFLAGS=-DFBR_LIBUNWIND
LIBUNWIND_LIB=-lunwind
LIBUNWIND=$(shell printf $(LIBUNWIND_C) | $(TCC) $(LIBUNWIND_LIB) $(TEST_TRUE))
ifeq ($(LIBUNWIND),true)
	CFLAGS_BUILD+=$(LIBUNWIND_CFLAGS)
	LIBFLAGS+=$(LIBUNWIND_LIB)
endif

# Release build (RELEASE=true)
RELEASE_CFLAGS=-DFBR_NO_ASSERT_DEV
ifeq ($(RELEASE),true)
	CFLAGS_BUILD+=$(RELEASE_CFLAGS)
endif

# Detect compiler
CFLAGS_CC=
ifeq ($(findstring clang,$(CC)),clang)
	CC_CLANG=true
	CFLAGS_CC=$(CFLAGS_CLANG)
endif
ifeq ($(findstring gcc,$(CC)),gcc)
	CC_GCC=true
	CFLAGS_CC=$(CFLAGS_GCC)
endif

# gcov
GCOV=gcov
GCOVFLAGS=-fprofile-arcs -ftest-coverage --coverage
GCOVLIBFLAGS=-lgcov
LCOV=lcov --capture --no-external --directory ./
LCOVHTML=genhtml
GCOV_FILE=$(BUILD)/coverage.info
GCOV_REPORT=report

# afl
AFL_CC=afl-clang-fast
AFL_CFLAGS_CC=$(CFLAGS_CLANG)

.PHONY:		all lib clean gcov gcovclean afl

all:		chttp_client fjson_client fiberfs_test lib
lib:		libfiberfs.so libchttp.a libfjson.a

chttp_client:	libchttp.a $(CHTTP_CLIENT_OBJS)
		$(CC) -o $@ $(CHTTP_CLIENT_OBJS) libchttp.a $(LIBFLAGS)

fjson_client:	libfjson.a $(FJSON_CLIENT_OBJS)
		$(CC) -o $@ $(FJSON_CLIENT_OBJS) libfjson.a $(LIBFLAGS_TEST)

fiberfs_test:	libchttp.a libfjson.a $(TEST_OBJS) $(OBJS)
		$(CC) -o $@ $(TEST_OBJS) $(OBJS) libchttp.a libfjson.a $(LIBFLAGS_TEST)

libfiberfs.so:	$(OBJS) libchttp.a libfjson.a
		$(CC) $(LDFLAGS) -o $@ $(OBJS) libchttp.a libfjson.a

libchttp.a:	$(CHTTP_OBJS)
		ar cr $@ $(CHTTP_OBJS)

libfjson.a:	$(FJSON_OBJS) $(UTILS_OBJS)
		ar cr $@ $(FJSON_OBJS) $(UTILS_OBJS)

$(BUILD)/%.o:	%.c | $(BUILD_DIRS)
		$(CC) $(CFLAGS) $(CFLAGS_CC) $(CFLAGS_BUILD) $(DEPFLAGS) -c $< -o $@

$(BUILD_DIRS):
		@mkdir -p $@

include $(wildcard $(DEPS))

clean:		gcovclean
		$(RMDIR) $(BUILD)
		$(RM) *.so *.a
		$(RM) chttp_client fjson_client fiberfs_test

gcov:		CFLAGS+=$(GCOVFLAGS)
gcov:		LIBFLAGS+=$(GCOVLIBFLAGS)
gcov:		clean
		$(MAKE) all CFLAGS="$(CFLAGS)" LIBFLAGS="$(LIBFLAGS)"
		$(MAKE) -C ../tests all error FLAGS=-vv
		$(GCOV) -r *.c */*.c */*/*.c */*/*/*.c
		$(LCOV) --output-file $(GCOV_FILE)
		$(LCOVHTML) $(GCOV_FILE) --output-directory $(GCOV_REPORT)

gcovclean:
		$(RMDIR) $(GCOV_REPORT)

#afl:		export AFL_USE_ASAN=1
#afl:		export AFL_USE_MSAN=1
afl:		clean
		$(MAKE) all CC=$(AFL_CC) CFLAGS_CC="$(AFL_CFLAGS_CC)"
