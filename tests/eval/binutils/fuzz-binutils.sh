#!/usr/bin/env bash


if [[ $# == 0 ]]; then
	echo "Usage: fuzz-binutils.sh /path/to/binutils/build"
	exit 1
fi

BINUTILS_DIR=$1
TIME=`date +%s`

for util in ar elfedit nm-new objcopy objdump ranlib readelf size strings strip-new sysinfo; do
	UTIL_PATH=$BINUTILS_DIR/$util
	OUT_PATH=$util/$TIME
	if [ ! -f $UTIL_PATH ]; then
		echo "Could not find $UTIL_PATH"
		continue
	fi
	mkdir -p $OUT_PATH
	../../../src/fosbin-sleuth/qemu-afl/fuzz-applications.py -pindir ../../../src/pin/pin-3.7/ \
		-tool ../../../cmake-build-debug/pintools/intel64/fosbin-zergling.so \
		-bin $UTIL_PATH
	mv *.ctx *.log $OUT_PATH
done