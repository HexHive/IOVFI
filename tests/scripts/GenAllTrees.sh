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
PINDIR=$TOP_DIR/src/pin-3.11/pin-3.11-3.7
IGNORE_FILE=$(realpath $3)
TIME_FILE=timing.txt

for d in $(find $COREUTILS_DIR -maxdepth 1 -type d -name "build-*-O*"); do
  CURR_DIR=$(basename $d)
  if [ -f "$CURR_DIR/tree.bin" ]; then
    continue
  fi
  if [ ! -d "$CURR_DIR" ]; then
    mkdir $CURR_DIR
  fi
  cd $CURR_DIR
  if [ ! -f "$TIME_FILE" ] || [ -z "$(grep "Fuzz End" $TIME_FILE)" ]; then
    echo "Fuzz Start: $(date)" >$TIME_FILE
    python3 $TOP_DIR/src/fosbin-sleuth/python/fuzz-applications.py -pindir $PINDIR -tool $PINTOOL -ignore $IGNORE_FILE -bin $d/src/$TREE_BIN
    echo "Fuzz End: $(date)" >>$TIME_FILE
  fi
  if [ -z "$(grep "Consolidation End" $TIME_FILE)" ]; then
    echo "Consolidation Start: $(date)" >>$TIME_FILE
    python3 $TOP_DIR/src/fosbin-sleuth/python/ConsolidateContexts.py -pindir $PINDIR -tool $PINTOOL -ignore $IGNORE_FILE
    echo "Consolidation End: $(date)" >>$TIME_FILE
  fi
  if [ -z "$(grep "Tree Generation End" $TIME_FILE)" ]; then
    echo "Tree Generation Start: $(date)" >>$TIME_FILE
    python3 $TOP_DIR/src/fosbin-sleuth/python/GenDecisionTree.py
    echo "Tree Generation End: $(date)" >>$TIME_FILE
  fi
  rm -rf logs/ _work/
  cd $CWD
done
