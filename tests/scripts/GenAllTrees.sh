#!/bin/bash

if [[ $# != 3 ]]; then
  echo "Usage: $(basename $0) /path/to/coreutils /path/to/FOSbin-flop /path/to/ignore/file"
  exit 1
fi

CWD=$(pwd)
TREE_BIN=$(basename $CWD)
COREUTILS_DIR=$(realpath $1)
TOP_DIR=$(realpath $2)
PINTOOL=$TOP_DIR/cmake-build-debug/pintools/intel64/fosbin-zergling.so
PINDIR=$TOP_DIR/src/pin/pin-3.7
IGNORE_FILE=$(realpath $3)
TIME_FILE=timing.txt

for d in $(find $COREUTILS_DIR -maxdepth 1 -type d -name "build-*"); do
  CURR_DIR=$(basename $d)
  cmd="mkdir $CURR_DIR; "
  cmd+="cd $CURR_DIR; "
  cmd+="echo \"Fuzz Start: $(date)\" > $TIME_FILE; "
  cmd+="$TOP_DIR/src/fosbin-sleuth/python/fuzz-applications.py -pindir $PINDIR -tool $PINTOOL -ignore $IGNORE_FILE -bin $d/src/$TREE_BIN; "
  cmd+="echo \"Fuzz End: $(date)\" >> $TIME_FILE; "
  cmd+="echo \"Consolidation Start $(date)\" >> $TIME_FILE; "
  cmd+="$TOP_DIR/src/fosbin-sleuth/python/ConsolidateContexts.py -pindir $PINDIR -tool $PINTOOL -ignore $IGNORE_FILE; "
  cmd+="echo \"Consolidation End $(date)\" >> $TIME_FILE; "
  cmd+="cd $CWD; "
  echo $cmd
done