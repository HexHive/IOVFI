#!/usr/bin/python3

import argparse
import os
import pickle
from contexts.FBDecisionTree import FBDecisionTree
from contexts import binaryutils
import random
import threading
from concurrent import futures
import multiprocessing
from contexts.FBLogging import logger
import logging

dangerous_functions = {'kill', '_exit', 'exit', '__kill', '_Exit', }
error_lock = threading.RLock()
error_msgs = list()

guesses = dict()
guess_lock = threading.RLock()

guessLoc = None

guessLocBase = ".guesses.bin"

pinLoc = None
pintoolLoc = None
binaryLoc = None
fbDtree = None

WORK_DIR = os.path.abspath(os.path.join("_work", "identifying"))


def check_inputs(argparser):
    global pinLoc, pintoolLoc, binaryLoc, guessLoc
    if not os.path.exists(argparser.tree):
        logger.fatal("Could not find {}".format(argparser.tree))
        exit(1)

    if not os.path.exists(argparser.binary):
        logger.fatal("Could not find {}".format(argparser.binary))
        exit(1)
    binaryLoc = os.path.abspath(argparser.binary)

    pinLoc = os.path.abspath(os.path.join(argparser.pindir, "pin"))
    pintoolLoc = os.path.abspath(argparser.tool)

    if not os.path.exists(pinLoc):
        logger.fatal("Could not find {}".format(pinLoc))
        exit(1)

    if not os.path.exists(pintoolLoc):
        logger.fatal("Could not find {}".format(pintoolLoc))
        exit(1)

    guessLoc = os.path.abspath(argparser.guesses)


def single_test(func_desc):
    global error_msgs, pinLoc, pintoolLoc, fbDtree

    try:
        guess = fbDtree.identify(func_desc, pinLoc, pintoolLoc, cwd=WORK_DIR)
        guess_lock.acquire()
        guesses[func_desc] = guess
        guess_lock.release()
    except Exception as e:
        error_lock.acquire()
        error_msgs.append(str(e))
        logger.exception("Error: {}".format(e))
        error_lock.release()
        guess_lock.acquire()
        guesses[func_desc] = FBDecisionTree.UNKNOWN_FUNC
        guess_lock.release()


def main():
    global fbDtree, guessLoc, binaryLoc, guesses

    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="/path/to/decision/tree", default="tree.bin")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-b", "--binary", help="/path/to/binary", required=True)
    parser.add_argument("-loglevel", help="Set log level", default=logging.DEBUG)
    parser.add_argument("-logprefix", help="Prefix to use before log files", default="")
    parser.add_argument("-threads", help="Number of threads to use", default=multiprocessing.cpu_count() * 5, type=int)
    parser.add_argument("-target", help="Location or function name to target")
    parser.add_argument("-guesses", help="/path/to/guesses", default="guesses.bin")
    results = parser.parse_args()

    logger.info("Checking inputs...")
    check_inputs(results)
    logger.info("done!")

    logpath = os.path.abspath(os.path.join("logs", "identifying", results.logprefix))
    if not os.path.exists(logpath):
        os.makedirs(logpath, exist_ok=True)
    loghandler = logging.FileHandler(os.path.join(logpath, os.path.basename(binaryLoc) + ".log"), mode="w")
    logger.addHandler(loghandler)
    logger.setLevel(results.loglevel)

    logger.info("Parsing tree at {}...".format(os.path.abspath(results.tree)))
    with open(results.tree, "rb") as treeFile:
        fbDtree = pickle.load(treeFile)
    logger.info("done!")

    logger.info("Analyzing {}".format(binaryLoc))

    if os.path.exists(guessLoc):
        msg = "Opening guesses at {}...".format(guessLoc)
        with open(guessLoc, "rb") as guessFile:
            guesses = pickle.load(guessFile)
        logger.info(msg + "done!")

    msg = "Finding functions in {}...".format(binaryLoc)
    location_map = binaryutils.find_funcs(binaryLoc, results.target)
    logger.info(msg + "done!")
    logger.info("Found {} functions".format(len(location_map)))

    random.seed()
    args = list()
    for loc, func_desc in location_map.items():
        if func_desc.name in dangerous_functions or func_desc.name in guesses.keys():
            logger.info("Skipping {}".format(func_desc.name))
            continue
        args.append(func_desc)

    if len(args) > 0:
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            pool.map(single_test, args)

        with open(guessLoc, "wb+") as guessFile:
            pickle.dump(guesses, guessFile)

    if len(error_msgs) > 0:
        logger.info("++++++++++++++++++++++++++++++++++++++++++++")
        logger.info("                  Errors                    ")
        logger.info("++++++++++++++++++++++++++++++++++++++++++++")
        logger.info(error_msgs)

    logger.info("++++++++++++++++++++++++++++++++++++++++++++")
    logger.info("                  Guesses                   ")
    logger.info("++++++++++++++++++++++++++++++++++++++++++++")
    for func_desc, guess in guesses.items():
        indicator = "X"
        guess_descs = fbDtree.get_equiv_classes(guess)

        if FBDecisionTree.UNKNOWN_FUNC == guess:
            indicator = "?"
        else:
            for func in guess_descs:
                if func.name.find(func_desc.name) >= 0:
                    indicator = "!"
                    break

        guess_list = list()
        for tmp in guess_descs:
            guess_list.append(str(tmp))
        logger.info("[{}] {}: {}".format(indicator, func_desc.name, " ".join(guess_list)))


if __name__ == "__main__":
    main()
