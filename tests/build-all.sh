#!/bin/bash

make clean
make

if [[ $? != 0 ]]; then
    exit $?
fi

mkdir desc/

for t in `ls build/`; do
    BIN=$PWD/build/$t
    ./scripts/create-desc.sh $BIN > desc/$t.desc
done
