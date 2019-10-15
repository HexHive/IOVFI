#!/bin/bash

if [[ $# != 3 ]]; then
  echo "Usage: $(basename "$0") /path/to/openssl /path/to/install/path"
  exit 1
fi

START_DIR=$PWD
OPENSSL_DIR=$(realpath "$1")
INSTALL_DIR=$(realpath "$2")

cd $OPENSSL_DIR

for d in $(find INSTALL_DIR -maxdepth 1 -mindepth 1 -type d); do
  git checkout $(basename $d)
  if [[ $? != 0 ]]; then
    echo "Failed to checkout tag $(basename $d)"
    continue
  fi
  ./config --prefix=$(realpath $d) --openssldir=$(realpath $d)/ssl
  if [[ $? != 0 ]]; then
    echo "Config failed for $(basename $d)"
    continue
  fi
  make
  if [[ $? != 0 ]]; then
    echo "Make failed for $(basename $d)"
    continue
  fi
  make install
  if [[ $? != 0 ]]; then
    echo "Make install failed for $(basename $d)"
    continue
  fi
done

cd $START_DIR