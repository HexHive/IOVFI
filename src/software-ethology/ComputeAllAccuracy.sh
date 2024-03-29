#!/bin/bash

tree_progs=("wc" "uniq" "realpath")
test_progs=("dir" "dirname" "du" "ls" "ptx" "sort" "true" "uname" "whoami")
comp_envs=("clang-O0" "gcc-O0" "clang-O1" "gcc-O1" "clang-O2" "gcc-O2" "clang-O3" "gcc-O3")

echo "" > results.csv

for tree_prog in "${tree_progs[@]}"
do
  if [ ! -d $tree_prog ]; then
    continue
  fi
  for tree_env in "${comp_envs[@]}"
  do
    for test_prog in "${test_progs[@]}"
    do
      for test_env in "${comp_envs[@]}"
      do
        python3 /home/derrick/code/FOSbin-flop/src/software-ethology/python/ComputeAccuracy.py -s \
        -tree $tree_prog/dtree-$tree_env/tree.bin \
        -g $tree_prog/dtree-$tree_env/$test_env/$test_prog/guesses.txt \
        -o $tree_prog/dtree-$tree_env/singleton-accuracy.bin \
        -tree_label dtree-$tree_env -compilation_label $test_env

        echo -n "," >> results.csv
      done
    done
    echo "" >> results.csv
  done
  echo "\n" >> results.csv
done
