#!/bin/bash

make clean
make

if [[ $? != 0 ]]; then
    exit $?
fi

for t in `ls build/`; do
    IFS=', ' read -r -a array <<< $(readelf -S build/$t 2> /dev/null | awk '{ if($3 == ".text") { print $5 "," $6;} }')
    TEXT_VA=0x${array[0]}
    TEXT_OFFSET=0x${array[1]}

    readelf -s build/$t | \
        awk -v text_va=$TEXT_VA -v text_off=$TEXT_OFFSET -v bin=$PWD/build/$t \
        'BEGIN { print "binary=" bin; } { if($4 == "FUNC") { va = "0x"$2; printf "addr=0x%x\n", (va - text_va + text_off); } }' > desc/$t.desc
done
