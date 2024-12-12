#!/bin/bash

AFL=afl-fuzz
AFL_MEMORY_MB=50
AFL_TIMEOUT_MS=2000
AFL_TESTS=../003_json/good_json
AFL_RESULTS=results
AFL_DICT=json.dict

FJSON=../../src/fjson_client

if [ ! -x "$(which $AFL)" ]
then
	echo "$AFL not found"
	exit 1
fi

if [ ! -x "$FJSON" ]
then
	echo "Binary not found: $FJSON"
	echo "Please run 'make afl'"
	exit 1
fi

export AFL_SKIP_CPUFREQ=1

$AFL -m $AFL_MEMORY_MB \
     -t $AFL_TIMEOUT_MS \
     -i $AFL_TESTS \
     -o $AFL_RESULTS \
     -x $AFL_DICT \
     -- $FJSON -f

if [ "$?" != "0" ]
then
	echo "Did you run 'make afl'?"
	exit 1
fi
