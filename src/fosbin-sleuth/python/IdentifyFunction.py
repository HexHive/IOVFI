#!/usr/bin/python3

import argparse
import os
import sys
import pickle
import random
from sklearn import tree
from contexts import IOVec


def attempt_ctx(iovec):
    return random.choice([True, False])


def main():
    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default="tree.bin")
    parser.add_argument('-m', '--map', help="Map of hashes and contexts", default="hash.map")
    parser.add_argument('-o', '--out', help="Output of which contexts execute with which functions", default="out.desc")
    # parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    # parser.add_argument("-tool", help="/path/to/pintool", required=True)
    results = parser.parse_args()

    if not os.path.exists(results.tree):
        print("Could not find {}".format(results.tree), file=sys.stderr)
        exit(1)

    if not os.path.exists(results.map):
        print("Could not find {}".format(results.map), file=sys.stderr)
        exit(1)

    if not os.path.exists(results.out):
        print("Could not find {}".format(results.out), file=sys.stderr)
        exit(1)

    treeFile = open(results.tree, "rb")
    fbDtree = pickle.load(treeFile)
    treeFile.close()

    hashFile = open(results.map, "rb")
    hashMap = pickle.load(hashFile)
    hashFile.close()

    descFile = open(results.out, "rb")
    descMap = pickle.load(descFile)
    descFile.close()

    dtree = fbDtree.dtree
    classifier = dtree.tree_
    idx = 0

    while idx < classifier.node_count:
        if classifier.children_left[idx] == classifier.children_right[idx]:
            print("Reached leaf")
            print(dtree.classes_[idx])
            break

        hash = fbDtree.labelEncoder.inverse_transform([classifier.feature[idx]])[0]
        iovec = hashMap[hash]
        if attempt_ctx(iovec):
            idx = classifier.children_right[idx]
        else:
            idx = classifier.children_left[idx]


if __name__ == "__main__":
    main()
