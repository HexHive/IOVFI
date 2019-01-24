#!/usr/bin/python3

import os
import sys
import subprocess
import argparse
from contexts import binaryutils
import logging
import multiprocessing
import threading
from concurrent import futures

fuzz_count = "5"
watchdog = 5 * 1000
work_dir = "contexts"

log = logging.getLogger(binaryutils.LOGGER_NAME)

failed_count = 0
fail_lock = threading.RLock()

success_count = 0
success_lock = threading.RLock()


def fuzz_one_function(args):
    cmd = args[0]
    binary = args[1]
    func_name = args[2]
    global failed_count
    global success_count
    try:
        log.info("Running {}".format(" ".join(cmd)))
        returnCode = subprocess.run(cmd, timeout=watchdog / 1000 + 1, cwd=os.path.abspath(work_dir))
        if returnCode.returncode != 0:
            fail_lock.acquire()
            failed_count += 1
            fail_lock.release()
        else:
            success_lock.acquire()
            success_count += 1
            log.info("Finished {}".format(func_name))
            success_lock.release()
    except subprocess.TimeoutExpired:
        fail_lock.acquire()
        failed_count += 1
        log.info("Finished {}".format(func_name))
        fail_lock.release()
    except Exception as e:
        fail_lock.acquire()
        log.error("Error for {}:{} : {}".format(binary, func_name, e))
        failed_count += 1
        fail_lock.release()


def main():
    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-bin", help="/path/to/target/application", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-funcs", help="/path/to/file/with/func/names")
    parser.add_argument("-log", help="/path/to/log/file")
    parser.add_argument("-loglevel", help="Level of output", default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", default=multiprocessing.cpu_count())

    results = parser.parse_args()
    if os.path.splitext(results.bin)[1] == ".so" and (results.ld is None or results.ld == ""):
        parser.print_help()
        exit(1)

    log.setLevel(results.loglevel)
    if results.log is not None:
        log.addHandler(logging.FileHandler(results.log, mode="w"))
        log.addHandler(logging.StreamHandler(sys.stdout))

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
        locationMap = dict()
        with open(results.funcs, "r") as f:
            count = 0
            for line in f.readlines():
                if line[0] != '.':
                    line = line.strip()
                    if line != "":
                        locationMap[count] = line.strip()
                        count += 1
    else:
        locationMap = binaryutils.find_funcs(results.bin)

    args = list()
    for location, func_name in locationMap.items():
        func_count += 1
        if '@' in func_name:
            func_name = func_name[:func_name.find("@")]

        if func_name in ignored_funcs:
            continue

        if os.path.splitext(results.bin)[1] == ".so":
            cmd = [os.path.join(os.path.abspath(results.pindir), "pin"), "-t", os.path.abspath(results.tool),
                   "-fuzz-count", fuzz_count,
                   "-shared-func", func_name, "-out", func_name + ".log", "-watchdog", str(watchdog), "--",
                   os.path.abspath(results.ld), os.path.abspath(results.bin)]
        else:
            cmd = [os.path.join(os.path.abspath(results.pindir), "pin"), "-t", os.path.abspath(results.tool),
                   "-fuzz-count", fuzz_count,
                   "-target", hex(location), "-out", str(func_name) + ".log", "-watchdog",
                   str(watchdog), "--", os.path.abspath(results.bin)]
        args.append([cmd, results.bin, func_name])

    if len(args) > 0:
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            try:
                pool.map(fuzz_one_function, args)
            except KeyboardInterrupt:
                exit(0)

        log.info("{} has {} functions".format(results.bin, func_count))
        log.info("Fuzzable functions: {}".format(success_count))
        if failed_count + success_count > 0:
            log.info("Failed functions: {} ({})".format(failed_count, failed_count / (failed_count + success_count)))
    else:
        log.fatal("Could not find any functions to fuzz")


if __name__ == "__main__":
    main()
