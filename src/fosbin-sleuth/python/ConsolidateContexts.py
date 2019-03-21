#!/usr/bin/python3.7

import sys
import os
import argparse
import pickle
from concurrent import futures
import multiprocessing
import datetime
import threading
from contexts import FBLogging
from contexts.PinRun import PinRun, PinMessage
import logging

logger = FBLogging.logger

WORK_DIR = os.path.join("_work", "consolidate")
LOG_DIR = os.path.join("logs", "consolidate")
watchdog = 0.5

desc_map = dict()
desc_file_path = None
desc_lock = threading.RLock()

pin_loc = None
pintool_loc = None
loader_loc = None

all_ctxs = set()
fuzzed_ctxs = None


def save_desc_for_later():
    global desc_map, desc_file_path
    if desc_file_path is not None:
        logger.info("Outputting desc_map to {}".format(desc_file_path))
        with open(desc_file_path, "wb") as file:
            desc_lock.acquire()
            try:
                pickle.dump(desc_map, file)
            except Exception as e:
                logger.exception(e)
            finally:
                desc_lock.release()


def consolidate_one_function(func_id):
    global desc_map, pin_loc, pintool_loc, loader_loc, watchdog, all_ctxs, fuzzed_ctxs

    # existing_ctxs = fuzzed_ctxs[func_id]

    run_name = os.path.basename(func_id.binary) + "." + func_id.name + "." + str(func_id.location)
    logger.info("{} starting".format(run_name))
    pipe_in = os.path.abspath(os.path.join(WORK_DIR, run_name + ".in"))
    pipe_out = os.path.abspath(os.path.join(WORK_DIR, run_name + ".out"))
    log_loc = os.path.abspath(os.path.join(LOG_DIR, run_name + ".consol.log"))
    cmd_log_loc = os.path.abspath(os.path.join(LOG_DIR, run_name + ".consol.cmd.log"))

    if not os.path.exists(WORK_DIR):
        os.makedirs(WORK_DIR, exist_ok=True)
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR, exist_ok=True)

    error_occurred = False
    lock_held = False

    pin_run = PinRun(pin_loc, pintool_loc, func_id.binary, loader_loc, pipe_in, pipe_out, log_loc,
                     os.path.abspath(WORK_DIR), cmd_log_loc)
    logger.debug("Created pin run for {}".format(run_name))
    for context in all_ctxs:
        # if context in existing_ctxs or func_id in desc_map[hash(context)]:
        #     logger.debug("Context {} skipped".format(context.hexdigest()))
        #     desc_map[hash(context)].add(func_id)
        #     continue

        try:
            if not pin_run.is_running():
                logger.debug("Starting pin_run for {}".format(run_name))
                pin_run.stop()
                pin_run.start(timeout=watchdog)
                ack_msg = pin_run.send_set_target_cmd(func_id.location, timeout=watchdog)
                if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                    logger.error("Set target ACK not received for {}".format(run_name))
                    break
                resp_msg = pin_run.read_response(timeout=watchdog)
                if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                    logger.error("Could not set target for {}".format(run_name))
                    break
                logger.debug("pin run started for {}".format(run_name))

            logger.debug("Sending reset command for {}".format(run_name))
            ack_msg = pin_run.send_reset_cmd(timeout=watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                logger.error("Reset ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=watchdog)
            if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                logger.error("Could not reset for {}".format(run_name))
                continue

            logger.debug("Sending set ctx command for {}".format(run_name))
            ack_msg = pin_run.send_set_ctx_cmd(context, timeout=watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=watchdog)
            if resp_msg is None or resp_msg.msgtype != PinMessage.ZMSG_OK:
                logger.error("Could not set context for {}".format(run_name))
                continue

            logger.debug("Sending execute command for {}".format(run_name))
            ack_msg = pin_run.send_execute_cmd(timeout=watchdog)
            if ack_msg is None or ack_msg.msgtype != PinMessage.ZMSG_ACK:
                logger.error("Set Context ACK not received for {}".format(run_name))
                continue
            resp_msg = pin_run.read_response(timeout=watchdog)
            if resp_msg is not None and resp_msg.msgtype == PinMessage.ZMSG_OK:
                desc_lock.acquire()
                lock_held = True
                desc_map[hash(context)].add(func_id)
                with open(desc_file_path, "wb") as desc_file:
                    pickle.dump(desc_map, desc_file)
                lock_held = False
                desc_lock.release()
                logger.info("{} accepts {}".format(run_name, context.hexdigest()))
            else:
                logger.info("{} rejects {}".format(run_name, context.hexdigest()))
        except AssertionError as e:
            if lock_held:
                lock_held = False
                desc_lock.release()
            logger.exception("Error for {}: {}".format(run_name, str(e)))
            logger.info("{} rejects {}".format(run_name, context.hexdigest()))
            pin_run.stop()
            continue
        except Exception as e:
            if lock_held:
                lock_held = False
                desc_lock.release()
            logger.exception("Error for {}: {}".format(run_name, str(e)))
            error_occurred = True
            break

    if lock_held:
        desc_lock.release()
    pin_run.stop()
    del pin_run
    if os.path.exists(pipe_in):
        os.unlink(pipe_in)
    if os.path.exists(pipe_out):
        os.unlink(pipe_out)
    logger.info("Finished {}".format(run_name))
    return error_occurred


def main():
    global desc_file_path, desc_map, pin_loc, pintool_loc, loader_loc, watchdog, all_ctxs, fuzzed_ctxs

    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument('-o', '--out', help="/path/to/output/function/descriptions", default="out.desc")
    parser.add_argument("-c", "--contexts", help="/path/to/existing/contexts", default="fuzz.ctx")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-log", help="/path/to/log/file", default="consolidation.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count() * 8)
    parser.add_argument("-timeout", help="Number of ms to wait for each context to finish completing", type=int,
                        default=watchdog)
    parser.add_argument("-singlectx")

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

    with open(results.contexts, "rb") as file:
        logger.info("Reading existing contexts")
        fuzzed_ctxs = pickle.load(file)
        logger.info("done")

    args = list()
    for func_id, ctxs in fuzzed_ctxs.items():
        for ctx in ctxs:
            hash_sum = hash(ctx)
            if hash_sum not in desc_map:
                desc_map[hash_sum] = set()
            if results.singlectx is None or ctx.hexdigest() == results.singlectx:
                all_ctxs.add(ctx)

        if results.target is None or func_id.name == results.target:
            args.append(func_id)

    logger.info("Number of unique IOVecs: {}".format(len(all_ctxs)))
    logger.info("Number of functions to test: {}".format(len(args)))

    if len(args) > 0:
        logger.info("Starting at {}".format(datetime.datetime.today()))
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            try:
                pool.map(consolidate_one_function, args)
            except KeyboardInterrupt as e:
                logger.exception("Pool canceled")
            except Exception as e:
                logger.exception(str(e))

        save_desc_for_later()
        # for arg in args:
        #     consolidate_one_function(arg)

        logger.debug("pool exited")
        if results.singlectx is None:
            for hash_sum, funcs in desc_map.items():
                func_str = ""
                for func in funcs:
                    func_str += str(func) + " "
                logger.info("{}: {}".format(hash_sum, func_str))
        logger.info("Consolidation complete at {}".format(datetime.datetime.today()))


if __name__ == "__main__":
    main()
