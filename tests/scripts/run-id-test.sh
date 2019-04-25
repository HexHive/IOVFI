#!/bin/bash

if [[ $# != 4 ]]; then
	echo "Usage: $(basename $0) /path/to/guess/dir /path/to/pin/dir /path/to/pintool /path/to/test/binaries"
	exit
fi

echo "$0 $1 $2 $3 $4" > cmd.txt
echo "Starting at `date`" >> cmd.txt

IGNORE_PATH=$(realpath $0/../ignored.txt)
DATA_DIR=$(realpath $1)
PIN=$(realpath $2)
PINTOOL=$(realpath $3)
TESTS=$(realpath $4)
ID_SCRIPT=$(realpath $(dirname $PINTOOL)/../../../src/fosbin-sleuth/python/IdentifyFunction.py)
CURR_DIR=$(pwd)
echo $CURR_DIR

for test in $(find $TESTS -type f -executable); do
	if [ -d "$(basename $test)" ]; then
		echo "Skipping $test"
        continue
	fi
	mkdir $(basename $test)
	cd $(basename $test)
	echo "Evaluating $test"
	cmd="$ID_SCRIPT -t $DATA_DIR/tree.bin -pindir $PIN -tool $PINTOOL -b $test"
	$cmd
	cd $CURR_DIR
done

echo "Ended at `date`" >> cmd.txt
