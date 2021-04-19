#!/usr/bin/python3.7

import argparse
import datetime
import logging
import multiprocessing as mp
import os
import pickle

import sys

from contexts import FBLogging
from contexts import binaryutils as bu
from contexts.SEGrindRun import SEGrindRun, SEMsgType

logger = FBLogging.logger

MAX_RETRY_COUNT = 3
WATCHDOG = 50.0

full_desc_map = dict()
GLOBAL_LOCK = mp.Lock()


class ConsolidationRunDesc(bu.RunDesc):
    def __init__(self, func_desc, valgrind_loc, work_dir, watchdog, contexts):
        bu.RunDesc.__init__(self, func_desc=func_desc,
                            valgrind_loc=valgrind_loc, work_dir=work_dir,
                            watchdog=watchdog)
        self.contexts = contexts


def consolidate_one_function(consolidation_run_desc):
    func_desc = consolidation_run_desc.func_desc

    work_dir = os.path.join(consolidation_run_desc.work_dir, "consolidate")
    log_dir = os.path.join("logs", "consolidate")

    run_name = os.path.basename(
        func_desc.binary) + "." + func_desc.name + "." + str(func_desc.location)
    pipe_in = os.path.abspath(os.path.join(work_dir, run_name + ".in"))
    pipe_out = os.path.abspath(os.path.join(work_dir, run_name + ".out"))
    log_loc = os.path.abspath(os.path.join(log_dir, run_name + ".consol.log"))
    cmd_log_loc = os.path.abspath(
        os.path.join(log_dir, run_name + ".consol.cmd.log"))
    # cmd_log_loc = os.path.abspath("/dev/null")

    desc_map = dict()

    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)

    logger.info("{} starting".format(run_name))
    segrind_run = SEGrindRun(valgrind_loc=consolidation_run_desc.valgrind_loc,
                             binary_loc=func_desc.binary,
                             pipe_in=pipe_in, pipe_out=pipe_out,
                             valgrind_log_loc=log_loc,
                             cwd=os.path.abspath(work_dir),
                             run_log_loc=cmd_log_loc)
    ctx_count = 0
    retry_count = 0
    idx = 0
    logger.debug("Created SEGrindRun for {}".format(run_name))
    while idx < len(consolidation_run_desc.contexts):
        iovec = consolidation_run_desc.contexts[idx]
        if retry_count > MAX_RETRY_COUNT:
            idx += 1
            retry_count = 0
            logger.error("{} failed to properly execute {}".format(run_name,
                                                                   iovec.hexdigest()))
            continue

        logger.info("{} testing {}".format(run_name, iovec.hexdigest()))
        try:
            if not segrind_run.is_running():
                logger.debug("Starting segrind_run for {}".format(run_name))
                segrind_run.stop()
                segrind_run.start(timeout=consolidation_run_desc.watchdog)

                ack_msg = segrind_run.send_set_target_cmd(func_desc.location,
                                                          timeout=consolidation_run_desc.watchdog)

                if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                    logger.error(
                        "Set target ACK not received for {}".format(run_name))
                    break
                resp_msg = segrind_run.read_response(
                    timeout=consolidation_run_desc.watchdog)
                if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                    logger.error("Could not set target for {}".format(run_name))
                    break
                logger.debug("SEGrindRun started for {}".format(run_name))
                ctx_count = 0
            ctx_count += 1

            # logger.debug("Sending reset command for {}".format(run_name))
            # ack_msg = segrind_run.send_reset_cmd(timeout=consolidation_run_desc.watchdog)
            # if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
            #     segrind_run.stop()
            #     retry_count += 1
            #     logger.error("Reset ACK not received foPinMessager {}".format(run_name))
            #     continue
            # resp_msg = segrind_run.read_response(timeout=consolidation_run_desc.watchdog)
            # if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
            #     segrind_run.stop()
            #     retry_count += 1
            #     logger.error("Could not reset for {}".format(run_name))
            #     if resp_msg is None:
            #         logger.error("{} Received no response back".format(run_name))
            #     else:
            #         logger.error("{} Received {} message".format(run_name, resp_msg.msgtype.name))
            #     continue

            logger.debug("Sending set ctx command for {}".format(run_name))
            ack_msg = segrind_run.send_set_ctx_cmd(iovec,
                                                   timeout=consolidation_run_desc.watchdog)
            if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                segrind_run.stop()
                retry_count += 1
                logger.error(
                    "Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = segrind_run.read_response(
                timeout=consolidation_run_desc.watchdog)
            if resp_msg is None or resp_msg.msgtype != SEMsgType.SEMSG_OK:
                segrind_run.stop()
                retry_count += 1
                logger.error("Could not set context for {}".format(run_name))
                if resp_msg:
                    logger.error(
                        "Received message {}".format(resp_msg.msgtype.name))
                continue

            logger.debug("Sending execute command for {}".format(run_name))
            ack_msg = segrind_run.send_execute_cmd(
                timeout=consolidation_run_desc.watchdog)
            if ack_msg is None or ack_msg.msgtype != SEMsgType.SEMSG_ACK:
                segrind_run.stop()
                retry_count += 1
                logger.error(
                    "Set Context ACK not received for {}".format(run_name))
                continue

            resp_msg = segrind_run.read_response(
                timeout=consolidation_run_desc.watchdog)
            if resp_msg is not None and resp_msg.msgtype == SEMsgType.SEMSG_OK:
                coverage = resp_msg.get_coverage()
                desc_map[hash(iovec)] = (func_desc, coverage)
                logger.info(
                    "{} accepts {} ({})".format(run_name, iovec.hexdigest(),
                                                ctx_count))
            else:
                logger.info(
                    "{} rejects {} ({})".format(run_name, iovec.hexdigest(),
                                                ctx_count))
            idx += 1
            retry_count = 0
        except AssertionError as e:
            logger.debug("Error for {}: {}".format(run_name, str(e)))
            logger.info("{} rejects {} ({})".format(run_name, iovec.hexdigest(),
                                                    ctx_count))
            idx += 1
            segrind_run.stop()
            continue
        except Exception as e:
            logger.exception("Error for {}: {}".format(run_name, str(e)))
            break

    segrind_run.stop()
    del segrind_run
    if os.path.exists(pipe_in):
        os.unlink(pipe_in)
    if os.path.exists(pipe_out):
        os.unlink(pipe_out)
    logger.info("Finished {}".format(run_name))
    return desc_map


def finish_consolidation(desc_map):
    global full_desc_map, GLOBAL_LOCK
    GLOBAL_LOCK.acquire()
    try:
        for hash_sum, (func_desc, coverage) in desc_map.items():
            if hash_sum not in full_desc_map:
                full_desc_map[hash_sum] = dict()
            full_desc_map[hash_sum][func_desc] = coverage
    except Exception as e:
        logger.error(str(e))
    finally:
        GLOBAL_LOCK.release()


def error_consolidation(err):
    logger.error(str(err))


def consolidate_contexts(valgrind_loc, num_threads, contexts_mapping,
                         watchdog=WATCHDOG,
                         work_dir=os.path.abspath(
                             os.path.join(os.curdir, "_work"))):
    if not os.path.exists(work_dir):
        os.makedirs(work_dir, exist_ok=True)

    consolidation_runs = list()
    for func_desc, contexts in contexts_mapping.items():
        consolidation_runs.append(
            ConsolidationRunDesc(func_desc, valgrind_loc, work_dir, watchdog,
                                 contexts))

    with mp.Pool(processes=num_threads) as pool:
        tasks = [
            pool.apply_async(consolidate_one_function, (consolidation_run,),
                             callback=finish_consolidation,
                             error_callback=error_consolidation) for
            consolidation_run in consolidation_runs]
        for task in tasks:
            task.wait()


def main():
    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument('-o', '--out',
                        help="/path/to/output/function/descriptions",
                        default="out.desc")
    parser.add_argument("-map", help="/path/to/context/map", default="hash.map")
    parser.add_argument("-valgrind", help="/path/to/pin-3.11/dir",
                        required=True)
    parser.add_argument("-target", help="Name of single function to target")
    parser.add_argument("-log", help="/path/to/log/file",
                        default="consolidation.log")
    parser.add_argument("-loglevel", help="Level of output", type=int,
                        default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int,
                        default=mp.cpu_count())
    parser.add_argument("-ignore", help="/path/to/ignored/functions")

    results = parser.parse_args()
    logger.setLevel(results.loglevel)
    if results.log is not None:
        logger.addHandler(logging.FileHandler(results.log, mode="w"))

    if not os.path.exists(results.map):
        logger.fatal("Could not find {}".format(results.map))
        sys.exit(1)

    valgrind_loc = os.path.abspath(results.valgrind)
    if not os.path.exists(valgrind_loc):
        logger.fatal("Could not find {}".format(valgrind_loc))
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

    all_func_descs = set()
    for func_desc in consolidation_map.keys():
        all_func_descs.add(func_desc)

    logger.info("Number of unique IOVecs: {}".format(len(hash_map)))
    logger.info(
        "Number of functions to test: {}".format(len(consolidation_map)))

    logger.info("Creating consolidation list")
    for hash_sum, io_vec in hash_map.items():
        if hash_sum in desc_map:
            for func_desc in all_func_descs:
                consolidation_map[func_desc].append(io_vec)
                # if func_desc not in desc_map[hash_sum]:
                #     consolidation_map[func_desc].append(io_vec)
    logger.info("Done")

    if len(consolidation_map) > 0:
        logger.info("Starting at {}".format(datetime.datetime.today()))
        consolidate_contexts(valgrind_loc, results.threads, consolidation_map)

        with open(desc_file_path, "wb") as file:
            pickle.dump(full_desc_map, file)

        logger.info(
            "Consolidation complete at {}".format(datetime.datetime.today()))


if __name__ == "__main__":
    main()
