#!/bin/bash

if [[ $# != 4 ]]; then
	echo "Usage: $(basename $0) /path/to/guess/dir /path/to/pin/dir /path/to/pintool /path/to/test/binaries"
	exit
fi

DATA_DIR=$(realpath $1)
PIN=$(realpath $2)
PINTOOL=$(realpath $3)
TESTS=$(realpath $4)
ID_SCRIPT=$(realpath $(dirname $PINTOOL)/../../../src/fosbin-sleuth/python/IdentifyFunction.py)

for test in $(find $TESTS -type f -executable); do
	if [ -d "$(basename $test)" ]; then
		continue
	fi
	mkdir $(basename $test)
	cd $(basename $test)
	echo "Evaluating $test"
	cmd="$ID_SCRIPT -t $DATA_DIR/tree.bin -pindir $PIN -tool $PINTOOL -b $test"
	$cmd
	cd ..
done
