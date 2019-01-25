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
import logging

dangerous_functions = {'kill', '_exit', 'exit', '__kill', '_Exit', }
error_lock = threading.RLock()
error_msgs = list()

guesses = dict()
guess_lock = threading.RLock()

guessLoc = None

guessLocBase = ".guesses.bin"

log = logging.getLogger(binaryutils.LOGGER_NAME)
log.setLevel(logging.INFO)

def check_inputs(argparser):
    if not os.path.exists(argparser.tree):
        log.fatal("Could not find {}".format(argparser.tree))
        exit(1)

    if not os.path.exists(argparser.binaries):
        log.fatal("Could not find {}".format(argparser.binaries))
        exit(1)


def single_test(args):
    global error_msgs
    loc = args[0]
    pindir = args[1]
    tool = args[2]
    binary = args[3]
    name = args[4]
    fbDtree = args[5]

    try:
        guess = fbDtree.identify(loc, pindir, tool, binary, name)
        guess_lock.acquire()
        guesses[name] = guess
        guess_lock.release()
    except Exception as e:
        error_lock.acquire()
        error_msgs.append(str(e))
        log.error("Error: {}".format(e))
        error_lock.release()
    except AssertionError as e:
        error_lock.acquire()
        error_msgs.append(str(e))
        log.error("Error: {}".format(e))
        error_lock.release()


def save_guesses_for_later():
    if guessLoc is not None:
        if not os.path.exists(os.path.dirname(guessLoc)):
            os.mkdir(os.path.dirname(guessLoc))
        with open(guessLoc, "wb+") as guessFile:
            pickle.dump(guesses, guessFile)
    exit(0)


def main():
    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="/path/to/decision/tree", default="tree.bin")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-b", "--binaries", help="/path/to/binary/list", required=True)
    parser.add_argument("-log", help="Set log level", default=logging.DEBUG)
    parser.add_argument("-threads", help="Number of threads to use", default=multiprocessing.cpu_count())
    parser.add_argument("-target", help="Location or function name to target")
    parser.add_argument("-verbose", help="Output more text", default=True)
    results = parser.parse_args()

    log.setLevel(results.log)
    log.addHandler(logging.StreamHandler(sys.stdout))

    log.info("Checking inputs...")
    check_inputs(results)
    log.info("done!")

    log.info("Parsing tree at {}...".format(results.tree))
    treeFile = open(results.tree, "rb")
    fbDtree = pickle.load(treeFile)
    treeFile.close()
    log.info("done!")

    with open(results.binaries, "r") as binaryFile:
        for binaryLoc in binaryFile.readlines():
            binaryLoc = os.path.abspath(binaryLoc.strip())
            if not os.path.exists(binaryLoc):
                log.error("Could not find {}".format(binaryLoc))
                continue

            basename = binaryLoc.replace(os.sep, ".")[19:]
            if not os.path.exists("logs"):
                os.mkdir("logs")

            loghandler = logging.FileHandler(os.path.join("logs", basename +
                ".log"), mode="w")
            log.addHandler(loghandler)
            global error_msgs
            error_msgs.clear()
            global guesses
            guesses.clear()

            global guessLoc
            guessLoc = os.path.join("guesses", basename + guessLocBase)

            if os.path.exists(guessLoc):
                msg = "Opening guesses at {}...".format(guessLoc)
                with open(guessLoc, "rb") as guessFile:
                    guesses = pickle.load(guessFile)
                log.info(msg + "done!")

            msg = "Finding functions in {}...".format(binaryLoc)
            location_map = binaryutils.find_funcs(binaryLoc, results.target)
            log.info(msg + "done!")
            log.info("Found {} functions".format(len(location_map)))

            random.seed()
            args = list()
            for loc, name in location_map.items():
                if name in dangerous_functions or name in guesses:
                    continue
                args.append([loc, results.pindir, results.tool, binaryLoc, name, fbDtree])

            if len(args) > 0:
                with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
                    try:
                        pool.map(single_test, args)
                    except KeyboardInterrupt:
                        save_guesses_for_later()

                if not os.path.exists("guesses"):
                    os.mkdir("guesses")
                with open(guessLoc, "wb+") as guessFile:
                    pickle.dump(guesses, guessFile)

            if len(error_msgs) > 0:
                log.info("++++++++++++++++++++++++++++++++++++++++++++")
                log.info("                  Errors                    ")
                log.info("++++++++++++++++++++++++++++++++++++++++++++")
                log.info(error_msgs)

            log.info("++++++++++++++++++++++++++++++++++++++++++++")
            log.info("                  Guesses                   ")
            log.info("++++++++++++++++++++++++++++++++++++++++++++")
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
                log.info("[{}] {}: {}".format(indicator, name, guess_names))
            log.removeHandler(loghandler)


if __name__ == "__main__":
    main()
