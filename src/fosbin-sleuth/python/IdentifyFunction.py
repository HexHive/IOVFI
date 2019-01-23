#!/usr/bin/python3

import argparse
import os
import sys
import pickle
from contexts.FBDecisionTree import FBDecisionTree
from contexts import binaryutils
import random

dangerous_functions = {'kill', '_exit', 'exit', '__kill', '_Exit', }

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
    error_msgs = list()
    random.seed()
    for loc, name in location_map.items():
        if name in dangerous_functions:
            continue

        try:
            guesses[name] = fbDtree.identify(loc, results.pindir, results.tool, results.binary, name, verbose=True)
        except Exception as e:
            error_msgs.append(str(e))
            print("Error: {}".format(e), file=sys.stderr)
            continue
        except AssertionError as e:
            error_msgs.append(str(e))
            print("Error: {}".format(e), file=sys.stderr)
            continue

    if (len(error_msgs) > 0):
        print("++++++++++++++++++++++++++++++++++++++++++++")
        print("                  Errors                    ")
        print("++++++++++++++++++++++++++++++++++++++++++++")
        print(error_msgs)

    print("++++++++++++++++++++++++++++++++++++++++++++")
    print("                  Guesses                   ")
    print("++++++++++++++++++++++++++++++++++++++++++++")
    for name, guess in guesses.items():
        indicator = "X"
        guess_names = fbDtree.get_equiv_classes(guess)

        if FBDecisionTree.UNKNOWN_FUNC == guess:
            indicator = "?"
        else:
            for func in guess_names:
                if func.find(name) >= 0:
                    indicator = "!"
                    break
        print("[{}] {}: {}".format(indicator, name, guess_names))


if __name__ == "__main__":
    main()
