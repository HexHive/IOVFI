#!/usr/bin/python3.7

import os
import subprocess
import argparse
from contexts import binaryutils
import multiprocessing
import threading
from concurrent import futures
from contexts.FBLogging import logger
import logging

fuzz_count = "5"
watchdog = 5 * 1000
work_dir = "contexts"

failed_count = 0
fail_lock = threading.RLock()

success_count = 0
success_lock = threading.RLock()

binary = None
pin_loc = None
pintool_loc = None
loader_loc = None


def fuzz_one_function(args):
    global failed_count, success_count, binary, target, pin_loc, pintool_loc, loader_loc
    target = args[0]
    func_name = args[1]
    if os.path.splitext(binary)[1] == ".so":
        target = func_name

    logger.debug("target = {} func_name = {}".format(target, func_name))
    out_contexts = os.path.join(work_dir, "{}.{}.ctx".format(os.path.basename(binary), func_name))

    try:
        pin_run = binaryutils.fuzz_function(binary, target, pin_loc, pintool_loc, cwd=work_dir, watchdog=watchdog,
                                            total_time=watchdog / 1000 + 1,
                                            log_loc=os.path.abspath(os.path.join(work_dir,
                                                                    "{}.{}.fuzz.log".format(os.path.basename(binary),
                                                                                            func_name))),
                                            loader_loc=loader_loc,
                                            out_contexts=out_contexts)

        logger.debug("{} pin_run.returncode = {}".format(out_contexts, pin_run.returncode()))
        if pin_run.returncode() != 0 and (os.path.exists(os.path.join(work_dir, out_contexts)) and os.path.getsize(
                os.path.join(work_dir, out_contexts)) == 0):
            logger.debug("{} failed".format(out_contexts))
            fail_lock.acquire()
            failed_count += 1
            fail_lock.release()
        else:
            logger.debug("{} succeeded".format(out_contexts))
            success_lock.acquire()
            success_count += 1
            success_lock.release()
    except subprocess.TimeoutExpired:
        logger.debug("{} failed".format(out_contexts))
        fail_lock.acquire()
        failed_count += 1
        fail_lock.release()
    except Exception as e:
        logger.debug("{} failed".format(out_contexts))
        fail_lock.acquire()
        logger.error("Error for {}.{}: {}".format(os.path.basename(binary), func_name, e))
        failed_count += 1
        fail_lock.release()
        raise e
    finally:
        logger.info("Finished {}".format(func_name))


def main():
    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-bin", help="/path/to/target/application", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-funcs", help="/path/to/file/with/func/names")
    parser.add_argument("-log", help="/path/to/log/file")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count())

    results = parser.parse_args()
    if os.path.splitext(results.bin)[1] == ".so" and (results.ld is None or results.ld == ""):
        parser.print_help()
        exit(1)

    global loader_loc, binary, pintool_loc, pin_loc
    loader_loc = results.ld
    binary = results.bin
    pintool_loc = results.tool
    pin_loc = os.path.join(results.pindir, "pin")

    logger.setLevel(results.loglevel)
    if results.log is not None:
        logger.addHandler(logging.FileHandler(results.log, mode="w"))

    func_count = 0
    ignored_funcs = set()
    if not os.path.exists(work_dir):
        os.mkdir(work_dir)

    if results.ignore is not None:
        with open(results.ignore) as f:
            for line in f.readlines():
                line = line.strip()
                ignored_funcs.add(line)

    if results.funcs is not None:
        location_map = dict()
        with open(results.funcs, "r") as f:
            for line in f.readlines():
                line = line.strip()
                temp = binaryutils.find_funcs(results.bin, line)
                for loc, name in temp.items():
                    location_map[loc] = name
    else:
        location_map = binaryutils.find_funcs(results.bin)

    args = list()
    for location, func_name in location_map.items():
        func_name = func_name.strip()
        func_count += 1
        if '@' in func_name:
            func_name = func_name[:func_name.find("@")]

        if func_name in ignored_funcs:
            continue

        args.append([location, func_name])

    if len(args) > 0:
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            try:
                pool.map(fuzz_one_function, args)
            except KeyboardInterrupt:
                exit(0)

        logger.info("{} has {} functions".format(results.bin, func_count))
        logger.info("Fuzzable functions: {}".format(success_count))
        if failed_count + success_count > 0:
            logger.info("Failed functions: {} ({})".format(failed_count, failed_count / (failed_count + success_count)))
    else:
        logger.fatal("Could not find any functions to fuzz")


if __name__ == "__main__":
    main()
