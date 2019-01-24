#!/usr/bin/python3

import os
import sys
import argparse
import pickle
from sklearn.externals.six import StringIO
from contexts.FBDecisionTree import FBDecisionTree
from contexts import binaryutils
import logging

TREE_OUT = "tree.bin"

log = logging.getLogger(binaryutils.LOGGER_NAME)

def main():
    parser = argparse.ArgumentParser(description="GenDecisionTree")
    parser.add_argument('-d', '--desc', help="Map of context hashes to functions that accept them",
                        default="out.desc")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default=TREE_OUT)
    parser.add_argument('-m', '--map', help="Map of hashes to contexts", default="hash.map")
    parser.add_argument('--dot', help="File to output tree dot file", default=TREE_OUT + ".dot")

    results = parser.parse_args()

    fbDtree = FBDecisionTree(results.desc, results.map)
    treeFile = open(results.tree, "wb+")
    pickle.dump(fbDtree, treeFile)

    msg = "Generating dot file..."
    dotFile = open(results.dot, "w+")
    sys.stdout.flush()
    dot_data = StringIO()
    fbDtree.export_graphviz(dot_data)
    dotFile.write(dot_data.getvalue())
    log.info(msg + "done!")


if __name__ == "__main__":
    main()
