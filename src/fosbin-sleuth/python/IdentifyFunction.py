#!/usr/bin/python3

import argparse
import os
import sys
import pickle
from contexts.FBDecisionTree import FBDecisionTree
from contexts import binaryutils
import random
import threading
from concurrent import futures
import multiprocessing
import signal

dangerous_functions = {'kill', '_exit', 'exit', '__kill', '_Exit', }
error_lock = threading.RLock()
error_msgs = list()

guesses = dict()
guess_lock = threading.RLock()

guessLoc = None


def check_inputs(argparser):
    if not os.path.exists(argparser.tree):
        print("Could not find {}".format(argparser.tree), file=sys.stderr)
        exit(1)

    if not os.path.exists(argparser.binary):
        print("Could not find {}".format(argparser.binary), file=sys.stderr)
        exit(1)


def single_test(args):
    loc = args[0]
    pindir = args[1]
    tool = args[2]
    binary = args[3]
    name = args[4]
    verbose = args[5]
    fbDtree = args[6]

    try:
        guess = fbDtree.identify(loc, pindir, tool, binary, name, verbose)
        guess_lock.acquire()
        guesses[name] = guess
        guess_lock.release()
    except Exception as e:
        error_lock.acquire()
        global error_msgs
        error_msgs.append(str(e))
        print("Error: {}".format(e), file=sys.stderr)
        error_lock.release()
    except AssertionError as e:
        error_lock.acquire()
        global error_msgs
        error_msgs.append(str(e))
        print("Error: {}".format(e), file=sys.stderr)
        error_lock.release()


def save_guesses_for_later():
    if guessLoc is not None:
        with open(guessLoc) as guessFile:
            pickle.dump(guesses, guessFile)
    exit(0)


def main():
    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default="tree.bin")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-b", "--binary", help="Binary to identify", required=True)
    parser.add_argument("-verbose", help="Print more info", default=True)
    parser.add_argument("-threads", help="Number of threads to use", default=multiprocessing.cpu_count())
    parser.add_argument("-guesses", help="/path/to/previous/run", default="guesses.bin")
    results = parser.parse_args()

    print("Checking inputs...", end='')
    check_inputs(results)
    print("done!")

    print("Parsing tree at {}...".format(results.tree), end='')
    treeFile = open(results.tree, "rb")
    fbDtree = pickle.load(treeFile)
    treeFile.close()
    print("done!")

    global guessLoc
    guessLoc = results.guesses
    if os.path.exists(guessLoc):
        print("Opening guesses at {}...".format(guessLoc), end='')
        with open(guessLoc, "rb") as guessFile:
            global guesses
            guesses = pickle.load(guessFile)
        print("done!")

    print("Finding functions in {}...".format(results.binary), end='')
    location_map = binaryutils.find_funcs(results.binary, results.target)
    print("done!")
    print("Found {} functions".format(len(location_map)))

    random.seed()
    args = list()
    for loc, name in location_map.items():
        if name in dangerous_functions or name in guesses:
            continue
        args.append([loc, results.pindir, results.tool, results.binary, name, results.verbose, fbDtree])

    if len(args) > 0:
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            try:
                pool.map(single_test, args)
            except KeyboardInterrupt:
                save_guesses_for_later()

        with open(guessLoc, "rb") as guessFile:
            pickle.dump(guesses, guessFile)

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
