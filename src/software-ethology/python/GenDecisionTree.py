#!/usr/bin/python3

import argparse
import logging
import pickle

from contexts.FBDecisionTree import FBDecisionTree
from contexts.FBLogging import logger

TREE_OUT = "tree.bin"


def main():
    parser = argparse.ArgumentParser(description="GenDecisionTree")
    parser.add_argument('-d', '--desc', help="Map of context hashes to functions that accept them",
                        default="out.desc")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default=TREE_OUT)
    parser.add_argument('-m', '--map', help="Map of hashes to contexts", default="hash.map")
    parser.add_argument("-log", help='/path/to/log/file', default="tree.log")

    results = parser.parse_args()
    logger.addHandler(logging.FileHandler(results.log, mode="w"))

    fbDtree = FBDecisionTree(results.desc, results.map)
    with open(results.tree, "wb+") as f:
        pickle.dump(fbDtree, f)


if __name__ == "__main__":
    main()
