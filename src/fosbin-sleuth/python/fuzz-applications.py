import argparse
import logging
import multiprocessing
import os
import pickle

from contexts import binaryutils
from contexts.FBLogging import logger

fuzz_count = 5


def main():
    global fuzz_count

    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-pindir", help="/path/to/pin-3.11/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-bin", help="/path/to/target/application", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-funcs", help="/path/to/file/with/func/names")
    parser.add_argument("-log", help="/path/to/log/file", default="fuzz.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=4 * multiprocessing.cpu_count())
    parser.add_argument("-map", help="/path/to/context/map", default="hash.map")
    parser.add_argument("-count", help="Number of times to fuzz function", type=int, default=fuzz_count)
    parser.add_argument('-o', '--out', help="/path/to/output/function/descriptions", default="out.desc")

    results = parser.parse_args()

    logger.setLevel(results.loglevel)
    logfile = os.path.abspath(results.log)
    if logfile is not None:
        if not os.path.exists(os.path.dirname(logfile)):
            os.makedirs(os.path.dirname(logfile), exist_ok=True)
        logger.addHandler(logging.FileHandler(logfile, mode="w"))

    if not os.path.exists(results.bin):
        logger.fatal("Could not find {}".format(results.bin))
        exit(1)

    if os.path.splitext(results.bin)[1] == ".so" and (results.ld is None or results.ld == ""):
        logger.fatal("Loader location is necessary")
        parser.print_help()
        exit(1)

    if results.ld is not None and not os.path.exists(results.ld):
        logger.fatal("Could not find loader {}".format(results.ld))
        exit(1)
    elif not os.path.exists(results.tool):
        logger.fatal("Could not find pintool {}".format(results.tool))
        exit(1)
    elif not os.path.exists(results.pindir):
        logger.fatal("Could not find pindir {}".format(results.pindir))
        exit(1)

    fuzz_count = results.count
    loader_loc = None
    if results.ld is not None:
        loader_loc = os.path.abspath(results.ld)

    pintool_loc = os.path.abspath(results.tool)
    pin_loc = os.path.abspath(os.path.join(results.pindir, "pin"))

    ignored_funcs = set()

    if results.ignore is not None:
        logger.debug("Reading ignored functions")
        with open(results.ignore) as f:
            for line in f.readlines():
                line = line.strip()
                ignored_funcs.add(line)
        logger.debug("done")

    if results.funcs is not None:
        logger.info("Finding specified functions")
        location_map = dict()
        with open(results.funcs, "r") as f:
            for line in f.readlines():
                line = line.strip()
                temp = binaryutils.find_funcs(results.bin, line, ignored_funcs)
                for loc, func_desc in temp.items():
                    location_map[loc] = func_desc
    else:
        logger.debug("Reading functions to fuzz")
        location_map = binaryutils.find_funcs(results.bin, ignored_funcs=ignored_funcs)
    logger.debug("done")

    hash_file = os.path.abspath(results.map)
    if not os.path.exists(os.path.dirname(hash_file)):
        os.makedirs(os.path.dirname(hash_file), exist_ok=True)

    map_file = os.path.abspath(results.out)
    if not os.path.exists(os.path.dirname(map_file)):
        os.makedirs(os.path.dirname(map_file), exist_ok=True)

    args = list()
    logger.debug("Building fuzz target list")
    func_count = len(location_map)
    for location, func_desc in location_map.items():
        args.append(func_desc)
    logger.debug("done")
    logger.info("Fuzzing {} targets".format(len(args)))

    if len(args) > 0:
        (fuzz_run_results, unclassified) = binaryutils.fuzz_functions(args, pin_loc, pintool_loc, loader_loc,
                                                                      results.threads, fuzz_count=results.count)

        logger.info("{} has {} functions".format(results.bin, func_count))
        logger.info("Fuzzable functions: {}".format(len(fuzz_run_results)))
        if len(unclassified) > 0:
            logger.info("Unclassified functions:")
            for func_desc in unclassified:
                logger.info(func_desc.name)

        context_hashes = dict()
        desc_map = dict()

        for func_desc, fuzz_run_result in fuzz_run_results.items():
            for hash_sum, io_vec in fuzz_run_result.io_vecs.items():
                context_hashes[hash_sum] = io_vec
                if hash_sum not in desc_map:
                    desc_map[hash_sum] = set()
                desc_map[hash_sum].add(func_desc)

        with open(hash_file, "wb") as hashes_out:
            pickle.dump(context_hashes, hashes_out)

        with open(map_file, "wb") as map_out:
            pickle.dump(desc_map, map_out)

    else:
        logger.fatal("Could not find any functions to fuzz")


if __name__ == "__main__":
    main()
