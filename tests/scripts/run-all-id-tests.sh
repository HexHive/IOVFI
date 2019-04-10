#!/usr/bin/env bash

if [[ $# != 4 ]]; then
	echo "Usage: $(basename $0) /path/to/test/dir /path/to/coreutils /path/to/pin/dir /path/to/pintool"
	exit 1
fi

START_PATH=$(realpath $1)
CURR_PWD=`pwd`
SCRIPT_LOC=$(realpath $(dirname $0))
COREUTILS_LOC=$(realpath $2)
PINDIR=$(realpath $3)
PINTOOL=$(realpath $4)

echo "START_PATH: $START_PATH"
echo "CURR_PWD: $CURR_PWD"
echo "SCRIPT_LOC: $SCRIPT_LOC"
echo "COREUTILS_LOC: $COREUTILS_LOC"
echo "PINDIR: $PINDIR"
echo "PINTOOL: $PINTOOL"

if [[ ! -e $START_PATH/tree.bin ]]; then
	echo "Could not find $START_PATH/tree.bin"
	exit 1
fi

cd $START_PATH

for testdir in $(find . -maxdepth 1 -type d); do
	if [[ $(realpath $testdir) == $START_PATH ]]; then
		continue
	fi
	cd $testdir
	cmd="$SCRIPT_LOC/run-id-test.sh $START_PATH $PINDIR $PINTOOL $COREUTILS_LOC/build-$(basename $testdir)/src"
	echo "Running command $cmd from $PWD"
	$cmd
    cd $START_PATH
done
