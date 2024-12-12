#!/bin/bash

AFL=afl-fuzz
AFL_MEMORY_MB=50
AFL_TIMEOUT_MS=2000
FJSON=../../src/fjson_client

if [ ! -x "$(which $AFL)" ]
then
	echo "$AFL not found"
	exit 1
fi

if [ ! -x "$FJSON" ]
then
	echo "Binary not found: $FJSON"
	echo "Please run 'make afl' in src directory"
	exit 1
fi

export AFL_SKIP_CPUFREQ=1

$AFL -m $AFL_MEMORY_MB \
     -t $AFL_TIMEOUT_MS \
     -i tests \
     -o results \
     -x json.dict \
     -- $FJSON -i

if [ "$?" != "0" ]
then
	echo "Did you run 'make afl' in the src directory?"
	exit 1
fi
