# FiberFS Makefile (src)

CC=gcc
CFLAGS=-O3 -Wall -Wextra -Wpedantic -Werror -g -fPIC -I. -Ichttp -Ifjson -fno-omit-frame-pointer
LDFLAGS=-shared
LIBFLAGS=
LIBFLAGS_TEST=-lpthread $(LIBFLAGS)

TEST_SRC:=$(wildcard test/*.c chttp/test/*.c fjson/test/*.c)
TEST_OBJS:=$(TEST_SRC:.c=.o)
TEST_INCLUDES:=$(wildcard test/*.h)

CHTTP_CLIENT:=$(wildcard chttp/client/*.c)
CHTTP_CLIENT_OBJS:=$(CHTTP_CLIENT:.c=.o)
CHTTP_SRC:=$(wildcard chttp/*.c chttp/*/*.c)
CHTTP_SRC:=$(filter-out $(TEST_SRC), $(CHTTP_SRC))
CHTTP_OBJS:=$(CHTTP_SRC:.c=.o)
CHTTP_TEST_INCLUDES:=$(wildcard chttp/test/*.h)
CHTTP_INCLUDES:=$(wildcard chttp/*.h chttp/*/*.h)
CHTTP_INCLUDES:=$(filter-out $(CHTTP_TEST_INCLUDES), $(CHTTP_INCLUDES))

FJSON_CLIENT:=$(wildcard fjson/client/*.c)
FJSON_CLIENT_OBJS:=$(FJSON_CLIENT:.c=.o)
FJSON_SRC:=$(wildcard fjson/*.c)
FJSON_SRC:=$(filter-out $(TEST_SRC), $(FJSON_SRC))
FJSON_OBJS:=$(FJSON_SRC:.c=.o)
FJSON_TEST_INCLUDES:=$(wildcard fjson/test/*.h)
FJSON_INCLUDES:=$(wildcard fjson/*.h)
FJSON_INCLUDES:=$(filter-out $(FJSON_TEST_INCLUDES), $(FJSON_INCLUDES))

INCLUDES:=$(wildcard *.h */*.h */*/*.h)
INCLUDES:=$(filter-out $(TEST_INCLUDES) $(CHTTP_INCLUDES) $(FJSON_INCLUDES), $(INCLUDES))
SOURCE:=$(wildcard *.c */*.c */*/*.c)
SOURCE:=$(filter-out $(TEST_SRC) $(CHTTP_CLIENT) $(CHTTP_SRC) $(FJSON_CLIENT), $(SOURCE))
OBJS:=$(SOURCE:.c=.o)

RM=rm -f
RMDIR=rm -rf
NULL=/dev/null
TEST_TRUE= > $(NULL) 2>&1 && echo true
TCC=$(CC) -x c - -o $(NULL)

# Detect openssl
OPENSSL_C='\#include <openssl/ssl.h>\nint main() {SSL *ssl;}'
OPENSSL_CFLAGS=-DCHTTP_OPENSSL
OPENSSL_LIB=-lssl -lcrypto
OPENSSL=$(shell printf $(OPENSSL_C) | $(TCC) $(OPENSSL_LIB) $(TEST_TRUE))
ifeq ($(OPENSSL),true)
	CFLAGS+=$(OPENSSL_CFLAGS)
	LIBFLAGS+=$(OPENSSL_LIB)
endif

# Detect zlib
ZLIB_C='\#include <zlib.h>\nint main() {zlibVersion();}'
ZLIB_CFLAGS=-DCHTTP_ZLIB
ZLIB_LIB=-lz
ZLIB=$(shell printf $(ZLIB_C) | $(TCC) $(ZLIB_LIB) $(TEST_TRUE))
ifeq ($(ZLIB),true)
	CFLAGS+=$(ZLIB_CFLAGS)
	LIBFLAGS+=$(ZLIB_LIB)
endif

# gcov
GCOV=gcov
GCOVFLAGS=-fprofile-arcs -ftest-coverage --coverage
GCOVLIBFLAGS=-lgcov
LCOV=lcov --capture --no-external --directory ./
LCOVHTML=genhtml
HTMLDIR=report

.PHONY:		all lib gcov clean cleanall

all:		chttp_client fjson_client fiberfs_test lib
lib:		libchttp.so libchttp.a libfjson.a

chttp_client:	libchttp.a $(CHTTP_CLIENT_OBJS)
		$(CC) -o $@ $(CHTTP_CLIENT_OBJS) libchttp.a $(LIBFLAGS)

fjson_client:	libfjson.a $(FJSON_CLIENT_OBJS)
		$(CC) -o $@ $(FJSON_CLIENT_OBJS) $(LIBFLAGS)

fiberfs_test:	libchttp.a libfjson.a $(TEST_OBJS)
		$(CC) -o $@ $(TEST_OBJS) libchttp.a libfjson.a $(LIBFLAGS_TEST)

libchttp.so:	$(CHTTP_OBJS)
		$(CC) $(LDFLAGS) -o $@ $(CHTTP_OBJS)

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

test/%.o:	test/%.c $(INCLUDES) $(TEST_INCLUDES) $(CHTTP_TEST_INCLUDES) $(FJSON_TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

chttp/test/%.o:	chttp/test/%.c $(CHTTP_INCLUDES) $(TEST_INCLUDES) $(CHTTP_TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

fjson/test/%.o:	fjson/test/%.c $(FJSON_INCLUDES) $(TEST_INCLUDES) $(FJSON_TEST_INCLUDES)
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		$(RM) *.o */*.o */*/*.o *.so *.a
		$(RM) chttp_client fjson_client fiberfs_test
		$(RM) *.gcno */*.gcno */*/*.gcno *.gcda */*.gcda */*/*.gcda
		$(RM) *.gcov */*.gcov */*/*.gcov
		$(RM) coverage.info gcov.data
		$(RMDIR) $(HTMLDIR)

cleanall:
		$(MAKE) clean
		$(MAKE) all

gcov:		gcov.data
		$(GCOV) -r *.c */*.c */*/*.c
		$(LCOV) --output-file coverage.info
		$(LCOVHTML) coverage.info --output-directory $(HTMLDIR)

gcov.data:	CFLAGS+=$(GCOVFLAGS)
gcov.data:	LIBFLAGS+=$(GCOVLIBFLAGS)
gcov.data:
		$(MAKE) cleanall CFLAGS="$(CFLAGS)" LIBFLAGS="$(LIBFLAGS)"
		$(MAKE) -C .. check FLAGS=-vv
		touch gcov.data
