#!/usr/bin/python3.7

import argparse
import datetime
import logging
import multiprocessing
import os
import pickle
import sys

from contexts import FBLogging, binaryutils

logger = FBLogging.logger

WATCHDOG = 0.5


def main():
    global WATCHDOG

    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument('-o', '--out', help="/path/to/output/function/descriptions", default="out.desc")
    parser.add_argument("-map", help="/path/to/context/map", default="hash.map")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-log", help="/path/to/log/file", default="consolidation.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count() * 8)
    parser.add_argument("-timeout", help="Number of ms to wait for each context to finish completing", type=float,
                        default=WATCHDOG)
    parser.add_argument("-singlectx")

    results = parser.parse_args()
    logger.setLevel(results.loglevel)
    if results.log is not None:
        logger.addHandler(logging.FileHandler(results.log, mode="w"))

    if not os.path.exists(results.map):
        logger.fatal("Could not find {}".format(results.map))
        sys.exit(1)

    watchdog = results.timeout

    pin_loc = os.path.abspath(os.path.join(results.pindir, "pin"))
    if not os.path.exists(pin_loc):
        logger.fatal("Could not find {}".format(pin_loc))
        sys.exit(1)

    pintool_loc = os.path.abspath(results.tool)
    if not os.path.exists(pintool_loc):
        logger.fatal("Could not find {}".format(pintool_loc))
        sys.exit(1)

    loader_loc = None
    if results.ld is not None:
        loader_loc = os.path.abspath(results.ld)
        if not os.path.exists(loader_loc):
            logger.fatal("Could not find {}".format(loader_loc))
            sys.exit(1)

    desc_file_path = os.path.abspath(results.out)

    if os.path.exists(desc_file_path):
        with open(desc_file_path, "rb") as file:
            if os.fstat(file.fileno()).st_size > 0:
                logger.info("Reading existing function descriptors")
                desc_map = pickle.load(file)
                logger.info("done")

    with open(results.map, "rb") as file:
        logger.info("Reading hash map file")
        hash_map = pickle.load(file)
        logger.info("done")

    consolidation_map = dict()

    for hash_sum, func_descs in desc_map.items():
        for func_desc in func_descs:
            if func_desc not in consolidation_map:
                consolidation_map[func_desc] = set()

    for hash_sum, io_vec in hash_map.items():
        consolidation_list = desc_map.keys()
        if hash_sum in desc_map:
            for func_desc in desc_map[hash_sum]:
                consolidation_list.remove(func_desc)

        for func_desc in consolidation_list:
            consolidation_map[func_desc].add(io_vec)

    logger.info("Number of unique IOVecs: {}".format(len(hash_map)))
    logger.info("Number of functions to test: {}".format(len(consolidation_map)))

    if len(consolidation_map) > 0:
        logger.info("Starting at {}".format(datetime.datetime.today()))
        new_desc_map = binaryutils.consolidate_contexts(pin_loc, pintool_loc, loader_loc, results.threads,
                                                        consolidation_map, watchdog=watchdog)
        for hash_sum, func_descs in new_desc_map.items():
            for func_desc in func_descs:
                desc_map[hash_sum].add(func_desc)

        with open(desc_file_path, "wb") as file:
            pickle.dump(desc_map, file)

        logger.info("Consolidation complete at {}".format(datetime.datetime.today()))


if __name__ == "__main__":
    main()
