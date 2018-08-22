#!/bin/bash

if [[ $# != 1 ]]; then
    echo "usage: $0 /path/to/binary"
    exit 1
fi

BIN=`realpath $1`

IFS=', ' read -r -a array <<< $(readelf -S $BIN 2> /dev/null | awk '{ if($3 == ".text") { print $5 "," $6;} }')
TEXT_VA=0x${array[0]}
TEXT_OFFSET=0x${array[1]}

readelf -s $BIN | \
    gawk -v text_va=$TEXT_VA -v text_off=$TEXT_OFFSET \
    '{ if($4 == "FUNC") { va = "0x"$2; printf \
    "0x%x=%s\n", (strtonum(va) - strtonum(text_va) + strtonum(text_off)), $NF; } }'
