#!/usr/bin/python3.7

import sys
import os
import argparse
import pickle
from concurrent import futures
import multiprocessing
import signal
import threading
from contexts import FBLogging
from contexts.PinRun import PinRun, PinMessage
import logging

logger = FBLogging.logger

WORK_DIR = "_work"
watchdog = 100

desc_map = dict()
desc_file_path = None
desc_lock = threading.RLock()

pin_loc = None
pintool_loc = None
loader_loc = None


def signal_handler(signal_id, frame):
    save_desc_for_later()
    sys.exit(signal_id)


def save_desc_for_later():
    global desc_map, desc_file_path
    if desc_file_path is not None:
        logger.info("Outputting desc_map to {}".format(desc_file_path))
        with open(desc_file_path, "wb") as file:
            desc_lock.acquire()
            pickle.dump(desc_map, file)
            desc_lock.release()


def consolidate_one_function(arg):
    global desc_map, pin_loc, pintool_loc, loader_loc, watchdog
    func_id = arg[0]
    contexts = arg[1]
    run_name = os.path.basename(func_id.binary) + "." + func_id.name + "." + str(func_id.location)
    pipe_in = os.path.abspath(os.path.join(WORK_DIR, run_name + ".in"))
    pipe_out = os.path.abspath(os.path.join(WORK_DIR, run_name + ".out"))
    log_loc = os.path.abspath(os.path.join("logs", run_name + ".log"))

    pin_run = PinRun(pin_loc, pintool_loc, func_id.binary, loader_loc, pipe_in, pipe_out, log_loc,
                     os.path.abspath(WORK_DIR))
    logger.debug("Created pin run for {}").format(run_name)
    for context in contexts:
        try:
            if not pin_run.is_running():
                pin_run.start(timeout=watchdog)
                ack_msg = pin_run.send_set_target_cmd(func_id.location, timeout=watchdog)
                if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                    logger.error("Set target ACK not received for {}".format(run_name))
                    break
                resp_msg = pin_run.read_response(timeout=watchdog)
                if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                    logger.error("Could not set target for {}".format(run_name))
                    break

            ack_msg = pin_run.send_reset_cmd(timeout=watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                logger.error("Reset ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=watchdog)
            if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                logger.error("Could not reset for {}".format(run_name))
                continue

            ack_msg = pin_run.send_set_ctx_cmd(context, timeout=watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=watchdog)
            if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                logger.error("Could not set context for {}".format(run_name))
                continue

            ack_msg = pin_run.send_execute_cmd(timeout=watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=watchdog)
            if resp_msg is not None and resp_msg.msgtype == PinMessage.ZMSG_OK:
                desc_lock.acquire()
                desc_map[hash(context)].append(func_id)
                desc_lock.release()
                logger.info("{} accepts {}".format(run_name, hash(context)))
            else:
                logger.info("{} rejects {}".format(run_name, hash(context)))
        except AssertionError as e:
            logger.exception("Error for {}: {}".format(run_name, str(e)))
            continue
        except Exception as e:
            logger.exception("Error for {}: {}".format(run_name, str(e)))
            break

    if pin_run.is_running():
        pin_run.stop()
    del pin_run
    logger.info("Finished {}".format(run_name))

def main():
    global desc_file_path, desc_map, pin_loc, pintool_loc, loader_loc, watchdog

    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument('-o', '--out', help="/path/to/output/function/descriptions", default="out.desc")
    parser.add_argument("-c", "--contexts", help="/path/to/existing/contexts", default="fuzz.ctx")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-log", help="/path/to/log/file", default="consolidation.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count())
    parser.add_argument("-timeout", help="Number of ms to wait for each context to finish completing", type=int,
                        default=watchdog)

    results = parser.parse_args()
    logger.setLevel(results.loglevel)
    if results.log is not None:
        logger.addHandler(logging.FileHandler(results.log, mode="w"))

    if not os.path.exists(results.contexts):
        logger.fatal("Could not find {}".format(results.contexts))
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

    with open(results.contexts) as file:
        logger.info("Reading existing contexts")
        existing_ctxs = pickle.load(file)
        logger.info("done")

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    all_ctxs = set()
    for func_id, ctxs in existing_ctxs.items():
        for ctx in ctxs:
            all_ctxs.add(ctx)

    logger.info("Unique contexts: {}".format(len(all_ctxs)))

    args = list()
    for func_id, ctxs in existing_ctxs.items():
        ctxs_to_test = set()
        for ctx in all_ctxs:
            if hash(ctx) not in desc_map:
                desc_map[hash(ctx)] = list()

            if ctx not in ctxs:
                ctxs_to_test.add(ctx)
            else:
                desc_map[hash(ctx)].append(func_id)

        if results.target is None or func_id.name == results.target:
            args.append([func_id, ctxs_to_test])

    with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
        pool.map(consolidate_one_function, args)

    save_desc_for_later()
    for hash_sum, funcs in desc_map.items():
        func_str = ""
        for func in funcs:
            func_str += str(func) + " "
        logger.info("{}: {}".format(hash_sum, func_str))


if __name__ == "__main__":
    main()
