#!/bin/bash

if [[ $# != 2 ]]; then
  echo "Usage: $(basename "$0") /path/to/libz/source /path/to/install/path"
  exit 1
fi

START_DIR=$PWD
LIBZ_DIR=$(realpath "$1")
INSTALL_DIR=$(realpath "$2")

cd $LIBZ_DIR

for d in $(find $INSTALL_DIR -maxdepth 1 -mindepth 1 -type d); do
  make clean
  git reset --hard HEAD
  git checkout $(basename $d)
  if [[ $? != 0 ]]; then
    echo "Failed to checkout tag $(basename $d)"
    continue
  fi
  ./configure
  if [[ $? != 0 ]]; then
    echo "Config failed for $(basename $d)"
    continue
  fi
  make
  if [[ $? != 0 ]]; then
    echo "Make failed for $(basename $d)"
    continue
  fi
  make install prefix=$d
  if [[ $? != 0 ]]; then
    echo "Make install failed for $(basename $d)"
    continue
  fi
done

cd $START_DIR
