#!/usr/bin/python3

import argparse
import os
import pickle
import sys


def main():
    parser = argparse.ArgumentParser(description=os.path.basename(sys.argv[0]))
    parser.add_argument('-o', '--out', help="/path/to/output/function/coverage/map", default="cov.map")
    parser.add_argument('-t', '--tree', help='/path/to/tree.bin', default='tree.bin')
    parser.add_argument('-h', '--hash', help='/path/to/hash.map', default='hash.map')
    parser.add_argument('-d', '--descs', help='/path/to/out.desc', default='out.desc')

    results = parser.parse_args()

    with open(results.tree, 'rb') as f:
        dtree = pickle.load(f)

    with open(results.hash, 'rb') as f:
        hashmap = pickle.load(f)

    with open(results.descs, 'rb') as f:
        func_descs = pickle.load(f)

    all_equiv_classes = dtree.get_all_equiv_classes()


if __name__ == "__main__":
    main()
