#!/bin/bash

ACCURACY_SCRIPT=$(realpath $(dirname $0)/../../src/fosbin-sleuth/python/ComputeAccuracy.py)
ROOT_DIR=$PWD

for dir in $(find $ROOT_DIR -mindepth 2 -maxdepth 2 -type d); do
  cd $dir
  for dir2 in $(find . -mindepth 1 -maxdepth 1 -type d); do
    cd $dir2
    find . -type f -name "guesses.bin" > guesses.txt
    python3 $ACCURACY_SCRIPT -tree ../tree.bin -o "../$dir2-guesses.bin"
  done
  cd $ROOT_DIR
done