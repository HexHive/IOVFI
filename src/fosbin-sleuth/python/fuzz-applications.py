#!/usr/bin/python3.7

import os
import argparse
from contexts import binaryutils
from contexts.PinRun import PinRun, PinMessage
from contexts.IOVec import IOVec
import multiprocessing
import threading
from concurrent import futures
from contexts.FBLogging import logger
import logging
import pickle

fuzz_count = 5
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

contexts = dict()


def fuzz_one_function(args):
    global failed_count, success_count, binary, target, pin_loc, pintool_loc, loader_loc, contexts
    target = args[0]
    func_name = args[1]
    if os.path.splitext(binary)[1] == ".so":
        target = func_name

    run_name = "{}.{}".format(os.path.basename(binary), func_name)
    pipe_in = run_name + ".in"
    pipe_out = run_name + ".out"
    log_out = os.path.join("logs", run_name + ".log")
    if not os.path.exists(os.path.dirname(log_out)):
        os.makedirs(os.path.dirname(log_out), exist_ok=True)
    successful_runs = 0

    if run_name in contexts:
        successful_contexts = contexts[run_name]
    else:
        successful_contexts = set()

    logger.debug("Creating PinRun for {}".format(run_name))
    pin_run = PinRun(pin_loc, pintool_loc, binary, loader_loc, pipe_in=pipe_in, pipe_out=pipe_out,
                     log_loc=log_out, cwd=work_dir)
    logger.debug("Done")
    try:
        logger.debug("Starting PinRun for {}".format(run_name))
        pin_run.start()
        if pin_run.send_set_target_cmd(target).msgtype != PinMessage.ZMSG_ACK or pin_run.read_response().msgtype != \
                PinMessage.ZMSG_OK:
            raise RuntimeError("Could not set target {}".format(target))

        for x in range(fuzz_count):
            pin_run.send_reset_cmd()

            if pin_run.send_fuzz_cmd().msgtype != PinMessage.ZMSG_ACK or pin_run.read_response().msgtype != \
                    PinMessage.ZMSG_OK:
                continue

            if pin_run.send_execute_cmd().msgtype != PinMessage.ZMSG_ACK:
                continue

            result = pin_run.read_response()
            if result.msgtype == PinMessage.ZMSG_OK:
                successful_runs += 1
                successful_contexts.add(IOVec(result.data))

        if successful_runs == 0:
            raise AssertionError("No successful runs")
        else:
            success_lock.acquire()
            success_count += 1
            contexts[run_name] = successful_contexts
            success_lock.release()
    except Exception as e:
        fail_lock.acquire()
        logger.error("Error for {}: {}".format(run_name, e))
        if success_count == 0:
            failed_count += 1
        fail_lock.release()
        raise e
    finally:
        logger.info("Finished {}".format(func_name))
        if pin_run.is_running():
            pin_run.stop()
        if os.path.exists(pipe_in):
            os.unlink(pipe_in)
        if os.path.exists(pipe_out):
            os.unlink(pipe_out)


def main():
    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-bin", help="/path/to/target/application", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-funcs", help="/path/to/file/with/func/names")
    parser.add_argument("-log", help="/path/to/log/file")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.DEBUG)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count())
    parser.add_argument("-ctx", help="File to output generated contexts", default="fuzz.ctx")

    results = parser.parse_args()
    if os.path.splitext(results.bin)[1] == ".so" and (results.ld is None or results.ld == ""):
        parser.print_help()
        exit(1)

    global loader_loc, binary, pintool_loc, pin_loc, contexts
    loader_loc = results.ld
    binary = results.bin
    pintool_loc = results.tool
    pin_loc = os.path.join(results.pindir, "pin")

    logger.setLevel(results.loglevel)
    logfile = os.path.abspath(results.log)
    if logfile is not None:
        if not os.path.exists(os.path.dirname(logfile)):
            os.makedirs(os.path.dirname(logfile), exist_ok=True)
        logger.addHandler(logging.FileHandler(logfile, mode="w"))

    func_count = 0
    ignored_funcs = set()
    if not os.path.exists(work_dir):
        os.mkdir(work_dir)

    if results.ignore is not None:
        logger.debug("Reading ignored functions")
        with open(results.ignore) as f:
            for line in f.readlines():
                line = line.strip()
                ignored_funcs.add(line)
        logger.debug("done")

    logger.debug("Reading functions to fuzz")
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
    logger.debug("done")

    context_file = os.path.abspath(results.ctx)
    if os.path.exists(context_file):
        logger.debug("Reading previous contexts")
        with open(context_file, "rb") as file:
            contexts = pickle.load(file)
        logger.debug("done")
    else:
        if not os.path.exists(os.path.dirname(context_file)):
            os.makedirs(os.path.dirname(context_file), exist_ok=True)

    args = list()
    logger.debug("Building fuzz target list")
    for location, func_name in location_map.items():
        func_name = func_name.strip()
        func_count += 1
        if '@' in func_name:
            func_name = func_name[:func_name.find("@")]

        if func_name in ignored_funcs:
            continue

        args.append([location, func_name])
    logger.debug("done")
    logger.info("Fuzzing {} targets".format(len(args)))

    if len(args) > 0:
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            try:
                pool.map(fuzz_one_function, args)
            except KeyboardInterrupt:
                exit(0)
        # for arg in args:
        #     fuzz_one_function(arg)

        logger.info("{} has {} functions".format(results.bin, func_count))
        logger.info("Fuzzable functions: {}".format(success_count))
        with open(context_file, "wb") as file:
            pickle.dump(contexts, file)

        if failed_count + success_count > 0:
            logger.info("Failed functions: {} ({})".format(failed_count, failed_count / (failed_count + success_count)))
    else:
        logger.fatal("Could not find any functions to fuzz")


if __name__ == "__main__":
    main()
