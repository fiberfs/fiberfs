# FiberFS Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -g -fPIC -I. -Ichttp -Ifjson -fno-omit-frame-pointer
CFLAGS_GCC=
CFLAGS_CLANG=-Wno-gnu-zero-variadic-macro-arguments
LDFLAGS=-shared
LIBFLAGS=
LIBFLAGS_TEST=-lpthread $(LIBFLAGS)

TEST_SRC:=$(wildcard test/*.c chttp/test/*.c fjson/test/*.c core/*/test/*.c)
TEST_OBJS:=$(TEST_SRC:.c=.o)
TEST_INCLUDES:=$(wildcard test/*.h)
TEST_INCLUDES_CORE:=$(wildcard core/*/test/*.h)

CHTTP_CLIENT:=$(wildcard chttp/client/*.c)
CHTTP_CLIENT_OBJS:=$(CHTTP_CLIENT:.c=.o)
CHTTP_SRC:=$(wildcard chttp/*.c chttp/*/*.c)
CHTTP_SRC:=$(filter-out $(TEST_SRC) $(CHTTP_CLIENT), $(CHTTP_SRC))
CHTTP_OBJS:=$(CHTTP_SRC:.c=.o)
CHTTP_TEST_INCLUDES:=$(wildcard chttp/test/*.h)
CHTTP_INCLUDES:=$(wildcard chttp/*.h chttp/*/*.h)
CHTTP_INCLUDES:=$(filter-out $(CHTTP_TEST_INCLUDES), $(CHTTP_INCLUDES))

FJSON_CLIENT:=$(wildcard fjson/client/*.c)
FJSON_CLIENT_OBJS:=$(FJSON_CLIENT:.c=.o)
FJSON_SRC:=$(wildcard fjson/*.c)
FJSON_SRC:=$(filter-out $(TEST_SRC) $(FJSON_CLIENT), $(FJSON_SRC))
FJSON_OBJS:=$(FJSON_SRC:.c=.o)
FJSON_TEST_INCLUDES:=$(wildcard fjson/test/*.h)
FJSON_INCLUDES:=$(wildcard fjson/*.h)
FJSON_INCLUDES:=$(filter-out $(FJSON_TEST_INCLUDES), $(FJSON_INCLUDES))

INCLUDES:=$(wildcard *.h */*.h */*/*.h)
INCLUDES:=$(filter-out $(TEST_INCLUDES) $(CHTTP_INCLUDES) $(CHTTP_TEST_INCLUDES) \
	$(FJSON_TEST_INCLUDES) $(FJSON_INCLUDES) $(TEST_INCLUDES_CORE), \
	$(INCLUDES))
SOURCE:=$(wildcard *.c */*.c */*/*.c)
SOURCE:=$(filter-out $(TEST_SRC) $(CHTTP_CLIENT) $(CHTTP_SRC) $(FJSON_CLIENT) $(FJSON_SRC), \
	$(SOURCE))
OBJS:=$(SOURCE:.c=.o)

RM=rm -f
RMDIR=rm -rf
PKG=pkg-config
NULL=/dev/null
TEST_TRUE= > $(NULL) 2>&1 && echo true
TCC=$(CC) -x c - -o $(NULL)

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
	CFLAGS+=$(FUSE3_CFLAGS)
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
	CFLAGS+=$(OPENSSL_CFLAGS)
	LIBFLAGS+=$(OPENSSL_LIB)
endif

# Detect zlib (ZLIB=false to disable)
ZLIB_PKG=zlib
ZLIB_C='\#include <zlib.h>\n int main() {zlibVersion();}'
ZLIB_CFLAGS=-DCHTTP_ZLIB
ZLIB_LIB=-lz
ZLIB=$(shell printf $(ZLIB_C) | $(TCC) $(ZLIB_LIB) $(TEST_TRUE))
ifeq ($(ZLIB),true)
	CFLAGS+=$(ZLIB_CFLAGS)
	LIBFLAGS+=$(ZLIB_LIB)
endif

# Detect compiler
ifeq ($(findstring clang,$(CC)),clang)
	CC_CLANG=true
	CFLAGS+=$(CFLAGS_CLANG)
endif
ifeq ($(findstring gcc,$(CC)),gcc)
	CC_GCC=true
	CFLAGS+=$(CFLAGS_GCC)
endif

# gcov
GCOV=gcov
GCOVFLAGS=-fprofile-arcs -ftest-coverage --coverage
GCOVLIBFLAGS=-lgcov
LCOV=lcov --capture --no-external --directory ./
LCOVHTML=genhtml
HTMLDIR=report

# afl
AFL_CC=afl-clang-fast
AFL_CFLAGS=
ifeq ($(CC_GCC),true)
	AFL_CFLAGS+=$(CFLAGS_CLANG)
endif

.PHONY:		all lib gcov clean

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

libfjson.a:	$(FJSON_OBJS)
		ar cr $@ $(FJSON_OBJS)

%.o:		%.c $(INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

chttp/%.o:	chttp/%.c $(CHTTP_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

fjson/%.o:	fjson/%.c $(FJSON_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

test/%.o:	test/%.c $(INCLUDES) $(TEST_INCLUDES) $(CHTTP_TEST_INCLUDES) \
			$(FJSON_TEST_INCLUDES) $(TEST_INCLUDES_CORE)
		$(CC) $(CFLAGS) -c $< -o $@

core/%/test/%.o: core/%/test/%.c $(INCLUDES) $(TEST_INCLUDES) $(TEST_INCLUDES_CORE)
		$(CC) $(CFLAGS) -c $< -o $@

chttp/test/%.o:	chttp/test/%.c $(CHTTP_INCLUDES) $(TEST_INCLUDES) $(CHTTP_TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

fjson/test/%.o:	fjson/test/%.c $(FJSON_INCLUDES) $(TEST_INCLUDES) $(FJSON_TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		$(RM) *.o */*.o */*/*.o */*/*/*.o *.so *.a
		$(RM) chttp_client fjson_client fiberfs_test
		$(RM) *.gcno */*.gcno */*/*.gcno *.gcda */*.gcda */*/*.gcda
		$(RM) *.gcov */*.gcov */*/*.gcov
		$(RM) coverage.info gcov.data
		$(RMDIR) $(HTMLDIR)

gcov:		gcov.data
		$(GCOV) -r *.c */*.c */*/*.c
		$(LCOV) --output-file coverage.info
		$(LCOVHTML) coverage.info --output-directory $(HTMLDIR)

gcov.data:	CFLAGS+=$(GCOVFLAGS)
gcov.data:	LIBFLAGS+=$(GCOVLIBFLAGS)
gcov.data:	clean
		$(MAKE) all CFLAGS="$(CFLAGS)" LIBFLAGS="$(LIBFLAGS)"
		$(MAKE) -C .. check FLAGS=-vv
		touch gcov.data

#afl:		export AFL_USE_ASAN=1
#afl:		export AFL_USE_MSAN=1
afl:		CC=$(AFL_CC)
afl:		CFLAGS+=$(AFL_CFLAGS)
afl:		clean
		$(MAKE) all CC=$(CC) CFLAGS="$(CFLAGS)"
