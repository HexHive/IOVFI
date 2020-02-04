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


def main():
    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument('-o', '--out', help="/path/to/output/function/descriptions", default="out.desc")
    parser.add_argument("-map", help="/path/to/context/map", default="hash.map")
    parser.add_argument("-pindir", help="/path/to/pin-3.11/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-target", help="Name of single function to target")
    parser.add_argument("-log", help="/path/to/log/file", default="consolidation.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count() * 8)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-singlectx")

    results = parser.parse_args()
    logger.setLevel(results.loglevel)
    if results.log is not None:
        logger.addHandler(logging.FileHandler(results.log, mode="w"))

    if not os.path.exists(results.map):
        logger.fatal("Could not find {}".format(results.map))
        sys.exit(1)

    pin_loc = os.path.abspath(os.path.join(results.pindir, "pin-3.11"))
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

    binaries = set()
    for hash_sum, func_descs in desc_map.items():
        for func_desc in func_descs:
            binaries.add(func_desc.binary)
            if results.target is None or func_desc.name == results.target:
                if func_desc not in consolidation_map:
                    consolidation_map[func_desc] = list()

    ignored_funcs = set()
    if results.ignore is not None:
        logger.debug("Reading ignored functions")
        with open(results.ignore) as f:
            for line in f.readlines():
                line = line.strip()
                ignored_funcs.add(line)
        logger.debug("done")

    for binary in binaries:
        logger.info("Finding functions in {}".format(binary))
        location_map = binaryutils.find_funcs(binary, ignored_funcs=ignored_funcs)
        for loc, func_desc in location_map.items():
            if func_desc not in consolidation_map:
                logger.info("Adding {}".format(func_desc.name))
                consolidation_map[func_desc] = list()

    all_func_descs = set()
    for func_desc in consolidation_map.keys():
        all_func_descs.add(func_desc)

    logger.info("Number of unique IOVecs: {}".format(len(hash_map)))
    logger.info("Number of functions to test: {}".format(len(consolidation_map)))

    logger.info("Creating consolidation list")
    for hash_sum, io_vec in hash_map.items():
        if hash_sum in desc_map:
            if results.singlectx is None:
                for func_desc in all_func_descs:
                    consolidation_map[func_desc].append(io_vec)
                    # if func_desc not in desc_map[hash_sum]:
                    #     consolidation_map[func_desc].append(io_vec)
            elif results.singlectx is not None and results.singlectx == io_vec.hexdigest():
                consolidation_map[func_desc].append(io_vec)
    logger.info("Done")

    if len(consolidation_map) > 0:
        logger.info("Starting at {}".format(datetime.datetime.today()))
        new_desc_map = binaryutils.consolidate_contexts(pin_loc, pintool_loc, loader_loc, results.threads,
                                                        consolidation_map)
        desc_map.clear()
        for hash_sum, func_descs in new_desc_map.items():
            for func_desc in func_descs:
                if hash_sum not in desc_map:
                    desc_map[hash_sum] = set()
                desc_map[hash_sum].add(func_desc)

        with open(desc_file_path, "wb") as file:
            pickle.dump(desc_map, file)

        logger.info("Consolidation complete at {}".format(datetime.datetime.today()))


if __name__ == "__main__":
    main()
