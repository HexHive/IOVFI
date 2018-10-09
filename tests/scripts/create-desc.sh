#!/bin/bash

if [[ $# != 1 ]]; then
    echo "usage: $0 /path/to/binary"
    exit 1
fi

BIN=`realpath $1`

if [[ $(file $BIN | grep "shared object") != "" ]]; then
    objdump -d $BIN | \
    gawk -v bin=$BIN \
    'BEGIN { print "binary=" bin; count = 0; } \
    { if(match($0, "[0-9a-fA-F]+ <[A-Za-z0-9_]+>:")) { addrs[count] = strtonum(sprintf("%s%s", "0x", $1)); \
                names[count] = substr($2, 2, length($2) - 3); \
                count++; } \
    } END { \
        for(i = 1; i < count; i++) { print "sym=" names[i - 1] "," addrs[i] - addrs[i - 1] } \
    }'
else
    IFS=', ' read -r -a array <<< $(readelf -S $BIN 2> /dev/null | awk '{ if($3 == ".text") { print $5 "," $6;} }')
    TEXT_VA=0x${array[0]}
    TEXT_OFFSET=0x${array[1]}

    IFS=', ' read -r -a array <<< $(readelf -S $BIN 2> /dev/null | awk '{ if($2 == ".bss") { offset=$5; } else if(offset != "") { print $1 "," offset; exit 0; } }')

    BSS_SIZE=0x${array[0]}
    BSS_OFFSET=0x${array[1]}

    readelf -s $BIN | \
        gawk -v text_va=$TEXT_VA -v text_off=$TEXT_OFFSET -v bin=$BIN \
        -v bss_size=$BSS_SIZE -v bss_off=$BSS_OFFSET \
        'BEGIN { print "binary=" bin; print "bss_offset=" bss_off; print "bss_size=" bss_size; } \
        { if($4 == "FUNC") { va = "0x"$2; printf "sym=0x%x,%d\n", (strtonum(va) - strtonum(text_va) + strtonum(text_off), $3);  } }'
fi
