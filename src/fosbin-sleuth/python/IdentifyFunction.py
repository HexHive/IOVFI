#!/usr/bin/python3

import argparse
import os
import sys
import pickle
from contexts.FBDecisionTree import FBDecisionTree
from contexts import binaryutils


def check_inputs(argparser):
    if not os.path.exists(argparser.tree):
        print("Could not find {}".format(argparser.tree), file=sys.stderr)
        exit(1)

    if not os.path.exists(argparser.binary):
        print("Could not find {}".format(argparser.binary), file=sys.stderr)
        exit(1)


def main():
    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default="tree.bin")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-b", "--binary", help="Binary to identify", required=True)
    results = parser.parse_args()

    print("Checking inputs...", end='')
    check_inputs(results)
    print("done!")

    print("Parsing tree at {}...".format(results.tree), end='')
    treeFile = open(results.tree, "rb")
    fbDtree = pickle.load(treeFile)
    treeFile.close()
    print("done!")

    print("Finding functions in {}...".format(results.binary), end='')
    location_map = binaryutils.find_funcs(results.binary, results.target)
    print("done!")
    print("Found {} functions".format(len(location_map)))

    guesses = dict()
    for loc, name in location_map.items():
        idx = 0
        guesses[name] = fbDtree.identify(loc, results.pindir, results.tool, results.binary, name)

    print("++++++++++++++++++++++++++++++++++++++++++++")
    print("                  Guesses                   ")
    print("++++++++++++++++++++++++++++++++++++++++++++")
    for name, guess in guesses.items():
        indicator = "X"
        print("{}: {}".format(name, guess))

        if name == FBDecisionTree.UNKNOWN_FUNC:
            indicator = "?"
        else:
            general_func_name = name[name.index("."):]

            for func in guess:
                if func.find(general_func_name) >= 0:
                    indicator = "!"
                    break
        print("[{}] {}: {}".format(indicator, name, guess))

if __name__ == "__main__":
    main()
