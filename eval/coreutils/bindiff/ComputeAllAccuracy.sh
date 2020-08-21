#!/bin/bash

tree_progs=("wc" "uniq" "realpath")
test_progs=("dir" "dirname" "du" "ls" "ptx" "sort" "true" "uname" "whoami")
comp_envs=("clang-O0" "gcc-O0" "clang-O1" "gcc-O1" "clang-O2" "gcc-O2" "clang-O3" "gcc-O3")

echo "" > results.csv

for tree_prog in "${tree_progs[@]}"
do
  for tree_env in "${comp_envs[@]}"
  do
    for test_prog in "${test_progs[@]}"
    do
      for test_env in "${comp_envs[@]}"
      do
        bindiff --output_format log --output_dir \
        `realpath results/$tree_prog/build-$tree_env/build-$test_env` \
        build-$tree_env/src/$tree_prog/$tree_prog.BinExport \
        build-$test_env/src/$test_prog/$test_prog.BinExport

        python3 ComputeAccuracy.py -b \
        results/$tree_prog/build-$tree_env/build-$test_env/"$tree_prog"_vs_"$test_prog".results >> results.csv

        echo -n "," >> results.csv
      done
    done
    echo "" >> results.csv
  done
  echo "\n" >> results.csv
done