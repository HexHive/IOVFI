#!/usr/bin/python3

import argparse
import logging
import multiprocessing
import os
import pickle
import random
import threading
from concurrent import futures

from contexts import binaryutils as bu
from contexts.FBLogging import logger

dangerous_functions = {'kill', '_exit', 'exit', '__kill', '_Exit', }
error_lock = threading.RLock()
error_msgs = list()

guesses = dict()
coverages = dict()
guess_lock = threading.RLock()

guessLoc = None

guessLocBase = ".guesses.bin"

binaryLoc = None
fbDtree = None
n_confirms = 1
valgrind_loc = None

WORK_DIR = os.path.abspath(os.path.join("_work", "identifying"))


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


def single_test(func_desc):
    global error_msgs, fbDtree, n_confirms, valgrind_loc

    coverage_window = 0.7

    try:
        log_names = bu.get_log_names(func_desc)
        log = os.path.join('logs', 'identify', log_names[0])
        cmd_log = os.path.join('logs', 'identify', log_names[1])
        guess, coverage = fbDtree.identify(func_desc=func_desc, valgrind_loc=valgrind_loc, cwd=WORK_DIR,
                                           max_confirm=n_confirms,
                                           cmd_log_loc=cmd_log, log_loc=log)

        # if guess is not None:
        #     tmp_coverages = list()
        #     ec_list = list(guess.equivalence_class)
        #     for ec in ec_list:
        #         tmp_coverages.append(tu.compute_path_coverage(fbDtree, ec.name))
        #     tmp_coverages.sort()
        #
        #     reachable_instructions_count = bu.compute_total_reachable_instruction_count(coverage)
        #     if reachable_instructions_count == 0:
        #         guess = None
        #     else:
        #         executed_instruction_count = bu.compute_total_executed_instruction_count(coverage)
        #         pct_cov = executed_instruction_count / reachable_instructions_count
        #         close_coverage = False
        #         for cov in tmp_coverages:
        #             if pct_cov * (1 - coverage_window) <= cov <= min(1.0, pct_cov * (1 + coverage_window)):
        #                 close_coverage = True
        #         if not close_coverage:
        # logger.info("Original guess removed for {} ({})".format(func_desc.name, " ".join([fd.name for fd
        #                                                                                   in ec_list
        #                                                                                   ])))
        # logger.info("\t{} vs. ({})".format(str(pct_cov), " ".join([str(c) for c in tmp_coverages])))
        # logger.info("\n{}: {}".format(func_desc.name, coverage))
        # for ec in ec_list:
        #     logger.info("{}: {}\n".format(ec.name, tu.get_tree_coverage(fbDtree, ec.name)))
        # logger.info("\n")
        # guess = None

        guess_lock.acquire()
        guesses[func_desc] = guess
        # coverages[func_desc] = coverage
        guess_lock.release()
    except Exception as e:
        error_lock.acquire()
        error_msgs.append(str(e))
        logger.exception("Error: {}".format(e))
        error_lock.release()
        guess_lock.acquire()
        guesses[func_desc] = None
        # coverages[func_desc] = None
        guess_lock.release()


def main():
    global fbDtree, guessLoc, binaryLoc, guesses, n_confirms, valgrind_loc

    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="/path/to/decision/tree", default="tree.bin")
    parser.add_argument('-valgrind', help='path/to/valgrind', required=True)
    parser.add_argument("-b", "--binary", help="/path/to/binary", required=True)
    parser.add_argument("-loglevel", help="Set log level", type=int, default=logging.INFO)
    parser.add_argument("-logprefix", help="Prefix to use before log files", default="")
    parser.add_argument("-threads", help="Number of threads to use", default=multiprocessing.cpu_count() * 8, type=int)
    parser.add_argument("-target", help="Location or function name to target")
    parser.add_argument("-guesses", help="/path/to/guesses", default="guesses.bin")
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-n", help="Number of confirmation checks", type=int, default=1)
    parser.add_argument('-outputonly', help='Only output the existing guesses', type=bool, default=False)
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

    if os.path.exists(guessLoc):
        msg = "Opening guesses at {}...".format(guessLoc)
        with open(guessLoc, "rb") as guessFile:
            guesses = pickle.load(guessFile)
        logger.info(msg + "done!")

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

        guess_list = list()
        if guess is None:
            indicator = "?"
        else:
            for func in guess.get_equivalence_class():
                if func.name.find(func_desc.name) >= 0:
                    indicator = "!"
                    break
            for func in guess.get_equivalence_class():
                guess_list.append(str(func))

        logger.info("[{}] {}: {}".format(indicator, func_desc.name, " ".join(guess_list)))
        # if guess is not None:
        #     tmp_coverages = list()
        #     for ec in guess.equivalence_class:
        #         tmp_coverages.append(tu.compute_path_coverage(fbDtree, ec.name))
        #     tmp_coverages.sort()
        #
        #     reachable_instructions_count = bu.compute_total_reachable_instruction_count(coverages[func_desc])
        #     executed_instruction_count = bu.compute_total_executed_instruction_count(coverages[func_desc])
        #     if executed_instruction_count > 0:
        #         logger.info("\tCoverage: {} vs. {} ({})".format(executed_instruction_count /
        #                                                         reachable_instructions_count,
        #                                                         statistics.mean(tmp_coverages),
        #                                                         " ".join([str(f) for f in tmp_coverages])))


if __name__ == "__main__":
    main()
