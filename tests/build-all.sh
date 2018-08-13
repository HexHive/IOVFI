#!/bin/bash

make clean
make

if [[ $? != 0 ]]; then
    exit $?
fi

for t in `ls build/`; do
    objdump -d build/$t | grep "[0-9a-f]* <[a-zA-Z0-9_]*>:" | \
        awk -v a="$PWD/build/$t" \
        'BEGIN { print "binary=" a } { printf "\naddr=0x%s", $1 }' \
        > desc/$t.desc
done
