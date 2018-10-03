#!/usr/bin/env bash

if [[ $# != 1 ]]; then
    echo "Usage: ./output-summary.sh /path/to/ground/truth.txt"
    exit 1
fi

TRUTH=$1
MAX_ARG=5

TOTAL_FUNCS=$(cat $TRUTH | wc -l)
IDENTIFIED_FUNCS=$(grep "^[1-9]" $TRUTH | wc -l)
CRASHED_FUNCS=$(grep "CRASHED" $TRUTH | wc -l)
FULL_MATCH=$(grep "True.*True" $TRUTH | wc -l)
MATCH_IN_SET=$(grep "False.*True" $TRUTH | wc -l)
INCORRECT_MATCH=$(grep "False.*False" $TRUTH | wc -l)

printf "Total Functions\tIdentified Functions\tCrashed Functions\tFull Match\tMatch in possible set\tIncorrect Match\n"
printf "$TOTAL_FUNCS\t\t$IDENTIFIED_FUNCS\t\t\t$CRASHED_FUNCS\t\t\t$FULL_MATCH\t\t$MATCH_IN_SET\t\t\t$INCORRECT_MATCH\n"

echo
echo "Sources of inaccuracy"
echo "---------------------"
NUM_DOUBLE=$(grep "False.*False.*<.*double.*>" $TRUTH | wc -l)
NUM_FLOAT=$(grep "False.*False.*<.*float.*>" $TRUTH | wc -l)
NUM_STRUCT=$(grep "False.*False.*\-> <.*struct.*>" $TRUTH | wc -l)
NUM_VARARGS=$(grep "False.*False.*\.\.\." $TRUTH | wc -l)
NUM_VA_LIST=$(grep "False.*False.*va_list" $TRUTH | wc -l)
NUM_ARG_COUNT=$(grep "False.*False" $TRUTH | awk -v MAX_ARG=$MAX_ARG '{ if($NF > MAX_ARG) { print $0; } }' | wc -l)
NUM_PTHREADS=$(grep "False.*False.*pthread" $TRUTH | wc -l)
NUM_UNIONS=$(grep "False.*False.*union" $TRUTH | wc -l)

printf "Number of floating point functions: %d\n" $(($NUM_DOUBLE+$NUM_FLOAT))
printf "Number of struct functions: %d\n" $NUM_STRUCT
printf "Number of varargs functions: %d\n" $(($NUM_VARARGS+NUM_VA_LIST))
printf "Number of functions with more than $MAX_ARG arguments: %d\n" $NUM_ARG_COUNT
printf "Number of functions with pthreads: %d\n" $NUM_PTHREADS
printf "Number of functions with unions: %d\n" $NUM_UNIONS

printf "\nTotal: %d\n" $(($NUM_PTHREADS+$NUM_ARG_COUNT+$NUM_VA_LIST+$NUM_VARARGS+$NUM_STRUCT+$NUM_DOUBLE+$NUM_FLOAT+$NUM_UNIONS))

# Print out set counts
echo
cat $TRUTH | awk '{ a[$1] = a[$1] + 1; } END { for(i = 0; i < 64; i++) { if(a[i] == 0) { print i " " 0; } else { print i " " a[i]; } } }'