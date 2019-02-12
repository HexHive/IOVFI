#!/usr/bin/python3.7

import os
import sys
import argparse
import pickle
import threading
from concurrent import futures
import multiprocessing
import signal
import struct
from contexts import IOVec, binaryutils, FBLogging, FunctionDescriptor
import logging

logger = FBLogging.logger

FIFO_PIPE_NAME = "fifo-pipe"
WORK_DIR = "_work"
watchdog = str(5 * 1000)

desc_map = dict()
desc_file = None
desc_lock = threading.RLock()

hash_map = dict()
hash_file = None
hash_lock = threading.RLock()

contexts = set()
contexts_lock = threading.RLock()

pin_loc = None
pintool_loc = None
loader_loc = None


def add_contexts(context_file):
    global contexts

    context_file = context_file.strip()
    io_vecs = read_contexts(context_file)
    # logger.debug("Attempting to get contexts_lock for {}".format(context_file))
    # contexts_lock.acquire()
    # logger.debug("{} got contexts_lock".format(context_file))
    for vec in io_vecs:
        logger.debug("{} adding IOVec {}".format(context_file, vec))
        contexts.add(vec)
    # contexts_lock.release()
    # logger.debug("{} released contexts_lock")


def read_contexts(context_file):
    results = list()
    context_file = context_file.strip()
    with open(context_file, 'rb') as f:
        logger.info("Reading {}".format(context_file))
        try:
            while f.tell() < os.fstat(f.fileno()).st_size:
                io_vec = IOVec.IOVec(f)
                results.append(io_vec)
        except IndexError as e:
            logger.error("IndexError")
        except struct.error as e:
            logger.error("Struct error")
        except MemoryError as e:
            logger.error("MemoryError")
        except OverflowError:
            logger.error("OverflowError")
        except ValueError:
            logger.error("ValueError")
        except Exception as e:
            logger.error("General Exception: {}".format(e))

    logger.debug("{} contained {} valid contexts".format(context_file, len(results)))
    return results


def signal_handler(signal, frame):
    save_desc_for_later()
    sys.exit(signal)


def save_desc_for_later():
    global desc_map, desc_file, hash_map, hash_file
    if desc_file is not None:
        logger.info("Outputting desc_map to {}".format(os.path.abspath(desc_file.name)))
        pickle.dump(desc_map, desc_file)
        desc_file.close()
        desc_file = None

    if hash_file is not None:
        logger.info("Outputting hash_map to {}".format(os.path.abspath(hash_file.name)))
        pickle.dump(hash_map, hash_file)
        hash_file.close()
        hash_file = None


def attempt_ctx(args):
    global pin_loc, pintool_loc, loader_loc, desc_map, hash_map
    binary = args[0]
    target = args[1]
    func_name = args[2]
    name = "{}.{}".format(os.path.basename(binary), target)
    in_contexts = os.path.join(WORK_DIR, FIFO_PIPE_NAME)
    out_contexts = os.path.join(WORK_DIR, "{}.all.ctx".format(name))
    cwd = WORK_DIR
    try:
        pin_run = binaryutils.fuzz_function(binary, target, pin_loc, pintool_loc, in_contexts=in_contexts, cwd=cwd,
                                            out_contexts=out_contexts, loader_loc=loader_loc, fuzz_count=0)
        if pin_run is not None:
            func_desc = FunctionDescriptor(binary, func_name, target)
            for io_vec in read_contexts(out_contexts):
                hash_sum = io_vec.hash()
                desc_lock.acquire()
                if hash_sum not in desc_map:
                    desc_map[hash_sum] = list()
                desc_map[hash_sum].append(func_desc)
                desc_lock.release()

                hash_lock.acquire()
                hash_map[hash_sum] = io_vec
                hash_lock.release()
    except TimeoutError:
        logger.error("{} timed out".format(name))
    except Exception as e:
        logger.error("Error categorizing {}: {}".format(name, e))
    finally:
        logger.info("Completed {}".format(name))


def main():
    parser = argparse.ArgumentParser(description="Consolidate")
    parser.add_argument("-b", "--binaries", help="File containing paths to binaries to test", required=True)
    parser.add_argument('-o', '--out', help="Output of which contexts execute with which functions", default="out.desc")
    parser.add_argument('-m', '--map', help="Map of hashes and contexts", default="hash.map")
    parser.add_argument("-c", "--contexts", help="File containing paths to contexts to use", required=True)
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-log", help="/path/to/log/file", default="consolidation.log")
    parser.add_argument("-loglevel", help="Level of output", type=int, default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count())

    results = parser.parse_args()
    logger.setLevel(results.loglevel)
    if results.log is not None:
        logger.addHandler(logging.FileHandler(results.log, mode="w"))

    if not os.path.exists(results.contexts):
        logger.fatal("Could not find {}".format(results.contexts))
        sys.exit(1)

    if not os.path.exists(results.binaries):
        logger.fatal("Could not find {}".format(results.binaries))
        sys.exit(1)

    global desc_file, desc_map, pin_loc, pintool_loc, loader_loc, contexts, hash_file
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

    if os.path.exists(results.out):
        desc_file = open(results.out, "rb")
        if os.fstat(desc_file.fileno()).st_size > 0:
            logger.info("Reading existing desc_file")
            desc_map = pickle.load(desc_file)
        desc_file.close()

    desc_file = open(results.out, "wb")
    hash_file = open(results.map, "wb")

    all_context_files = set()
    with open(results.contexts, "r") as contexts_file:
        for context_file in contexts_file:
            all_context_files.add(context_file.strip())

    with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
        pool.map(add_contexts, all_context_files)

    logger.info("Unique Hashes: {}".format(len(contexts)))
    sys.exit(0)

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    if not os.path.exists(WORK_DIR):
        os.mkdir(WORK_DIR)
    ctx_path = os.path.join(WORK_DIR, FIFO_PIPE_NAME)

    with open(ctx_path, "wb+") as ctxFile:
        logger.info("Writting contexts to {}".format(ctxFile))
        for io_vec in contexts:
            io_vec.write_bin(ctxFile)
        logger.info("done")

    with open(results.binaries, "r") as binaries:
        for binary in binaries.readlines():
            binary = os.path.abspath(binary.strip())

            msg = "Reading function locations for {}...".format(binary)
            location_map = binaryutils.find_funcs(binary, results.target)
            logger.info(msg + "done")

            args = list()
            for loc, name in location_map.items():
                args.append([binary, loc, name])

            if len(args) > 0:
                with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
                    try:
                        pool.map(attempt_ctx, args, timeout=int(watchdog) / 1000 + 2)
                    except futures.TimeoutError:
                        print("Too long")
                        pass

    save_desc_for_later()
    for hash_sum, funcs in desc_map.items():
        logger.info("{}: {}".format(hash_sum, funcs))


if __name__ == "__main__":
    main()
