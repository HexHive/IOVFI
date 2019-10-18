#!/bin/bash

function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

ZLIB_DIR=$(realpath $1)
START_DIR=$PWD
TOP_DIR="$(realpath $(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)/../../)"

for d in $(find $ZLIB_DIR -mindepth 1 -maxdepth 1 -type d); do
  for d2 in $(find $ZLIB_DIR -mindepth 1 -maxdepth 1 -type d); do
    if version_gt $d2 $d; then
      CURR_DIR=$(basename $d)/$(basename $d2)
      if [ ! -d $CURR_DIR ]; then
        mkdir -p $CURR_DIR
      fi
      cd $CURR_DIR
      if [ ! -f "guesses.bin" ]; then
        python3 $TOP_DIR/src/fosbin-sleuth/python/IdentifyFunction.py -pindir $TOP_DIR/src/pin/pin-3.7 \
          -tool $TOP_DIR/cmake-build-debug/pintools/intel64/fosbin-zergling.so \
          -t ../tree.bin -b $ZLIB_DIR/$d2/lib/libz.so \
          -ld $TOP_DIR/cmake-build-debug/bin/fb-load
      fi

      rm -rf logs/ _work/

      cd $START_DIR
    fi
  done
done
