#!/usr/bin/python3.7

import os
import sys
import argparse
import pickle
import subprocess
import threading
from concurrent import futures
import multiprocessing
import signal
import struct
from contexts import IOVec, binaryutils
import logging

log = logging.getLogger(binaryutils.LOGGER_NAME)

FIFO_PIPE_NAME = "fifo-pipe"
WORK_DIR = "_work"
watchdog = str(5 * 1000)

passingHashes = dict()
contextHashes = dict()

descMap = None
descFile = None
hashMap = dict()
invalid_contexts = set()
hashlock = threading.RLock()
invalidctx_lock = threading.RLock()
descMap_lock = threading.RLock()
print_lock = threading.RLock()


def read_contexts(contextFile):
    contextfile = contextFile.strip()
    with open(contextfile, 'rb') as f:
        log.info("Reading {}".format(contextfile))
        try:
            while f.tell() < os.fstat(f.fileno()).st_size:
                iovec = IOVec.IOVec(f)
                md5hash = iovec.hash()
                hashlock.acquire()
                hashMap[md5hash] = iovec
                hashlock.release()
        except IndexError as e:
            log.error("IndexError")
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except struct.error as e:
            log.error("Struct error")
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except MemoryError as e:
            log.error("MemoryError")
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except OverflowError:
            log.error("OverflowError")
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except ValueError:
            log.error("ValueError")
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except Exception as e:
            log.error("General Exception: {}".format(e))


def unique_identification(binary, name, hash_sum):
    return "{}.{}.{}".format(os.path.basename(binary), name, hash_sum)


def save_desc_for_later(signal, frame):
    if descFile is not None:
        pickle.dump(descMap, descFile)
    exit(0)


def attempt_ctx(args):
    binary = os.path.abspath(args[0])
    pindir = os.path.abspath(args[1])
    tool = os.path.abspath(args[2])
    hash_sum = args[3]
    loc = args[4]
    name = args[5]
    processedFile = args[6]

    if os.path.splitext(binary)[1] == ".so":
        loader = args[7]
        cmd = [os.path.join(pindir, "pin"), "-t", tool, "-fuzz-count", "0",
               "-out", name + ".log", "-watchdog", watchdog, "-shared-func", name,
               "-contexts", os.path.abspath(os.path.join(WORK_DIR, FIFO_PIPE_NAME)), "--", loader, binary]
    else:
        cmd = [os.path.join(pindir, "pin"), "-t", tool, "-fuzz-count", "0",
               "-target", hex(loc), "-out", name + ".log", "-watchdog", watchdog,
               "-contexts", os.path.abspath(os.path.join(WORK_DIR, FIFO_PIPE_NAME)), "--", binary]

    try:
        id = unique_identification(binary, name, hash_sum) + ".tmp"
        temp_file = open(id, "w+")
        temp_file.close()
        log.debug("cmd: {}".format(" ".join(cmd)))
        message = "Testing {}.{} ({}) with hash {}...".format(binary, name,
                hex(loc), hash_sum)
        fuzz_cmd = subprocess.run(cmd, capture_output=True, timeout=int(watchdog) / 1000 + 1, cwd=os.path.abspath(
            WORK_DIR))
        accepted = (fuzz_cmd.returncode == 0)

        if accepted:
            descMap_lock.acquire()
            descMap[hash_sum].append(os.path.basename(binary) + "." + name)
            descMap_lock.release()
            message += "accepted!"
        else:
            message += "failed"

        print_lock.acquire()
        log.info(message)
        print(id, file=processedFile)
        print_lock.release()
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print_lock.acquire()
        log.error("General exception: {}".format(e))
        print_lock.release()
    finally:
        if os.path.exists(id):
            os.unlink(id)


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
    parser.add_argument("-loglevel", help="Level of output", default=logging.INFO)
    parser.add_argument("-threads", help="Number of threads to use", type=int, default=multiprocessing.cpu_count())

    results = parser.parse_args()
    if not os.path.exists(results.contexts):
        log.fatal("Could not find {}".format(results.contexts))
        exit(1)

    if not os.path.exists(results.binaries):
        log.fatal("Could not find {}".format(results.binaries))
        exit(1)

    mapFile = open(results.map, "wb")

    log.setLevel(results.loglevel)
    if results.log is not None:
        log.addHandler(logging.FileHandler(results.log, mode="w"))
    log.addHandler(logging.StreamHandler(sys.stdout))

    global descMap
    descMap = dict()
    if os.path.exists(results.out):
        descFile = open(results.out, "rb")
        if os.fstat(descFile.fileno()).st_size > 0:
            descMap = pickle.load(descFile)
        descFile.close()

    descFile = open(results.out, "wb")
    processedFile = open("processed.txt", "a+")
    processedBinaries = set()
    for binary in processedFile.readlines():
        processedBinaries.add(binary)

    if os.path.exists(WORK_DIR):
        # shutils.rmtree still caused errors, so call in the big guns...
        os.system("rm -rf {}".format(WORK_DIR))

    os.mkdir(WORK_DIR)

    with open(results.contexts, "r") as contexts:
        with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
            pool.map(read_contexts, contexts)

    log.info("Unique Hashes: {}".format(len(hashMap)))
    pickle.dump(hashMap, mapFile)

    signal.signal(signal.SIGTERM, save_desc_for_later)

    with open(results.binaries, "r") as binaries:
        for binary in binaries.readlines():
            binary = binary.strip()
            binary = os.path.abspath(binary)


            msg = "Reading function locations for {}...".format(binary)
            location_map = binaryutils.find_funcs(binary, results.target)
            log.info(msg + "done")

            for hash_sum, iovec in hashMap.items():
                descMap[hash_sum] = list()
                ctxPath = os.path.join(WORK_DIR, FIFO_PIPE_NAME)
                if os.path.exists(ctxPath):
                    os.unlink(ctxPath)
                out_pipe = open(ctxPath, "wb")
                iovec.write_bin(out_pipe)
                out_pipe.close()

                args = list()
                for loc, name in location_map.items():
                    if unique_identification(binary, name, hash_sum) in processedBinaries:
                        continue

                    if '@' in name:
                        name = name[:name.find("@")]

                    if os.path.splitext(binary)[1] == ".so":
                        if results.ld is None or not os.path.exists(results.ld):
                            log.fatal("Could not find loader at {}".format(results.ld))
                            exit(1)

                        args.append(
                            [binary, os.path.abspath(results.pindir),
                             os.path.abspath(results.tool), hash_sum, loc, name,
                             processedFile, results.ld])
                    else:
                        args.append(
                            [binary, os.path.abspath(results.pindir),
                             os.path.abspath(results.tool), hash_sum, loc, name,
                             processedFile])

                if len(args) > 0:
                    with futures.ThreadPoolExecutor(max_workers=results.threads) as pool:
                        try:
                            pool.map(attempt_ctx, args)
                        except KeyboardInterrupt:
                            save_desc_for_later(signal.SIGTERM, None)

    pickle.dump(descMap, descFile)
    processedFile.close()
    for hash_sum, funcs in descMap.items():
        log.info("{}: {}".format(hash_sum, funcs))


if __name__ == "__main__":
    main()
