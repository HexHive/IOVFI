#!/usr/bin/python3

import sys, pickle

for tree_path in sys.argv[1:]:
    with open(tree_path, 'rb') as f:
        tree = pickle.load(f)

    total_size = 0
    iovec_count = 0
    for _, tree_map in tree.hashMaps.items():
        for _, iovec in tree_map.items():
            total_size += iovec.size_in_bytes()
            iovec_count += 1

    print("%s: %d / %d = %f" % (tree_path, total_size, iovec_count, total_size / iovec_count))
