#!/usr/bin/env bash


if [[ $# == 0 ]]; then
	echo "Usage: fuzz-coreutils.sh /path/to/coreutils/build"
	exit 1
fi

COREUTILS_DIR=$1
TIME=`date +%s`

for util in tsort printenv echo printf dirname false date sort basename sha1sum base64 sha256sum cat sha512sum sum seq true dir wc sha384sum tail uniq base32 head sha224sum cksum md5sum pwd ls whoami; do
	UTIL_PATH=$COREUTILS_DIR/$util
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