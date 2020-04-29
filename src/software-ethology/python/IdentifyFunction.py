#!/usr/bin/python3

import argparse
import logging
import multiprocessing as mp
import os
import pickle

from contexts import binaryutils as bu
from contexts.FBLogging import logger

dangerous_functions = {'kill', '_exit', 'exit', '__kill', '_Exit', }

guessLocBase = ".guesses.bin"

binaryLoc = None
fbDtree = None
n_confirms = 1
valgrind_loc = None

WORK_DIR = os.path.abspath(os.path.join("_work", "identifying"))
WATCHDOG = 3


def check_inputs(argparser):
    global valgrind_loc, binaryLoc, guessLoc
    if not os.path.exists(argparser.tree):
        logger.fatal("Could not find {}".format(argparser.tree))
        exit(1)

    if not os.path.exists(argparser.binary):
        logger.fatal("Could not find {}".format(argparser.binary))
        exit(1)
    binaryLoc = os.path.abspath(argparser.binary)

    guessLoc = os.path.abspath(argparser.guesses)
    valgrind_loc = os.path.abspath(argparser.valgrind)
    if not os.path.exists(valgrind_loc):
        logger.fatal("Could not find {}".format(valgrind_loc))
        exit(1)
    if argparser.timeout <= 0:
        logger.fatal("Invalid timeout value: {}".format(argparser.timeout))
        exit(1)


def single_test(func_desc, timeout, error_msgs):
    global fbDtree, n_confirms, valgrind_loc
    running_path = os.path.join("_work", "running", func_desc.name)
    os.makedirs(os.path.dirname(running_path), exist_ok=True)
    guess_equiv_class = list()
    try:
        log_names = bu.get_log_names(func_desc)
        with open("{}".format(running_path), 'w'):
            pass
        log = os.path.join('logs', 'identify', log_names[0])
        cmd_log = os.path.join('logs', 'identify', log_names[1])
        guess, coverage = fbDtree.identify(func_desc=func_desc, valgrind_loc=valgrind_loc, timeout=timeout,
                                           cwd=WORK_DIR, max_confirm=n_confirms, cmd_log_loc=cmd_log, log_loc=log)
        if guess is not None:
            for ec in guess.get_equivalence_class():
                guess_equiv_class.append(ec)
            guess_equiv_class.sort(key=lambda fd: fd.name)
    except Exception as e:
        guess_equiv_class = None
        error_msgs.append(str(e))
        logger.error("Error: {}".format(e))
    finally:
        logger.debug("Completed {}".format(func_desc.name))
        if os.path.exists(running_path):
            os.remove(running_path)
        return func_desc, guess_equiv_class


def main():
    global fbDtree, binaryLoc, n_confirms, valgrind_loc

    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="/path/to/decision/tree", default="tree.bin")
    parser.add_argument('-valgrind', help='path/to/valgrind', required=True)
    parser.add_argument("-b", "--binary", help="/path/to/binary", required=True)
    parser.add_argument("-loglevel", help="Set log level", type=int, default=logging.INFO)
    parser.add_argument("-logprefix", help="Prefix to use before log files", default="")
    parser.add_argument("-threads", help="Number of threads to use", default=mp.cpu_count(), type=int)
    parser.add_argument("-target", help="Location or function name to target")
    parser.add_argument("-guesses", help="/path/to/guesses", default="guesses.bin")
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-n", help="Number of confirmation checks", type=int, default=1)
    parser.add_argument('-outputonly', help='Only output the existing guesses', type=bool, default=False)
    parser.add_argument('-timeout', help='Time to wait for function to complete', type=int, default=WATCHDOG)
    results = parser.parse_args()

    logger.info("Checking inputs...")
    check_inputs(results)
    logger.info("done!")
    n_confirms = results.n

    logpath = os.path.abspath(os.path.join("logs", "identify", results.logprefix))
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

    if not results.outputonly:
        ignored_funcs = set()
        if results.ignore is not None:
            logger.debug("Reading ignored functions")
            with open(results.ignore) as f:
                for line in f.readlines():
                    line = line.strip()
                    ignored_funcs.add(line)
            logger.debug("done")

        msg = "Finding functions in {}...".format(binaryLoc)
        location_map = bu.find_funcs(binaryLoc, results.target, ignored_funcs)
        logger.info(msg + "done!")
        logger.info("Found {} functions".format(len(location_map)))

    guesses_out = dict()
    with mp.Manager() as manager:
        error_msgs = manager.list()

        args = list()
        for loc, func_desc in location_map.items():
            if func_desc.name in dangerous_functions:
                logger.info("Skipping {}".format(func_desc.name))
                continue
            args.append((func_desc, results.timeout, error_msgs))

        with mp.Pool(processes=results.threads) as pool:
            completed = [pool.apply_async(single_test, arg) for arg in args]
            for c in completed:
                (func_desc, guess) = c.get()
                guesses_out[func_desc] = guess

        logger.info("Completed identification")
        # for func_desc, guess in guesses.items():
        #     logger.debug("Recording {}".format(func_desc.name))
        #     guesses_out[func_desc] = guess

        if len(error_msgs) > 0:
            logger.info("++++++++++++++++++++++++++++++++++++++++++++")
            logger.info("                  Errors                    ")
            logger.info("++++++++++++++++++++++++++++++++++++++++++++")
            logger.info(error_msgs)

    logger.info("++++++++++++++++++++++++++++++++++++++++++++")
    logger.info("                  Guesses                   ")
    logger.info("++++++++++++++++++++++++++++++++++++++++++++")
    for func_desc, guess in guesses_out.items():
        indicator = "X"

        guess_list = list()
        if guess is None:
            indicator = "?"
        else:
            for func in guess:
                if func.name.find(func_desc.name) >= 0:
                    indicator = "!"
                    break
            for func in guess:
                guess_list.append(str(func))

        logger.info("[{}] {}: {}".format(indicator, func_desc.name, " ".join(guess_list)))

    with open(guessLoc, 'wb') as f:
        pickle.dump(guesses_out, f)


if __name__ == "__main__":
    main()
