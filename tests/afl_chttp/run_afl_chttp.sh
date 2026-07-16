#!/bin/bash

AFL=afl-fuzz
AFL_MEMORY_MB=50
AFL_TIMEOUT_MS=2000
AFL_INPUT=examples
AFL_RESULTS=results
AFL_DICT=http.dict

CHTTP=../../src/chttp_fuzz

if [ ! -x "$(which $AFL)" ]
then
	echo "$AFL not found"
	exit 1
fi

if [ ! -x "$CHTTP" ]
then
	echo "Binary not found: $CHTTP"
	echo "Please run 'make afl'"
	exit 1
fi

if [ -d "$AFL_RESULTS" ]
then
	AFL_INPUT=-
fi

export AFL_SKIP_CPUFREQ=1

$AFL -m $AFL_MEMORY_MB \
     -t $AFL_TIMEOUT_MS \
     -i "$AFL_INPUT" \
     -o "$AFL_RESULTS" \
     -x "$AFL_DICT" \
     -- $CHTTP _stdin

if [ "$?" != "0" ]
then
	echo "Did you run 'make afl'?"
	exit 1
fi
