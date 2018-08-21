#!/bin/bash

if [[ $# != 2 ]]; then
    echo "usage: $0 <path to binary> <path to output>"
    exit 1
fi

BIN=$1
OUT=$2

IFS=', ' read -r -a array <<< $(readelf -S $BIN 2> /dev/null | awk '{ if($3 == ".text") { print $5 "," $6; } }')
TEXT_VA=0x${array[0]}
TEXT_OFFSET=0x${array[1]}

ADDRS=`grep -i positive $OUT | gawk -v text_va=$TEXT_VA -v text_off=$TEXT_OFFSET \
    '{ if (!addrs[$6]) { addrs[$6] = $6; } } \
    END { for (addr in addrs) { printf "%x\n", (strtonum(addr) + strtonum(text_va) - strtonum(text_off)); } }'`

for addr in $ADDRS; do
    readelf -s $BIN | grep -i $addr | awk '{ i=0; while (i < NF) { printf "%s: %s\n", $(i+2), $(i+8); i += 8; } }'
done
