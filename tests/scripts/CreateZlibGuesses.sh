#!/bin/bash

function version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

ZLIB_DIR=$(realpath $1)
START_DIR=$PWD

for d in $(find $ZLIB_DIR -mindepth 1 -maxdepth 1 -type d); do
  for d2 in $(find $ZLIB_DIR -mindepth 1 -maxdepth 1 -type d); do
    if version_gt $d2 $d1; then
      echo "mkdir $d/$d2"
    fi
  done
done