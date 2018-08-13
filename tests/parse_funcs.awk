BEGIN{ printf "binary=%s\n", $BIN_NAME; }

{
    printf "addr=0x$s\n", $1;
}