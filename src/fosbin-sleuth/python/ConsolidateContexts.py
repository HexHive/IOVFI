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
from contexts import IOVec

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
max_workers = multiprocessing.cpu_count()


def read_contexts(contextFile):
    contextfile = contextFile.strip()
    with open(contextfile, 'rb') as f:
        print("Reading {}".format(contextfile))
        try:
            while f.tell() < os.fstat(f.fileno()).st_size:
                iovec = IOVec.IOVec(f)
                md5hash = iovec.hash()
                hashlock.acquire()
                hashMap[md5hash] = iovec
                hashlock.release()
        except IndexError as e:
            print("IndexError", file=sys.stderr)
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except struct.error as e:
            print("Struct error", file=sys.stderr)
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except MemoryError as e:
            print("MemoryError", file=sys.stderr)
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except OverflowError:
            print("OverflowError", file=sys.stderr)
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except ValueError:
            print("ValueError", file=sys.stderr)
            invalidctx_lock.acquire()
            invalid_contexts.add(contextfile)
            invalidctx_lock.release()
        except Exception as e:
            print("General Exception: {}".format(e))


def unique_identification(binary, name, hash):
    return "{}.{}.{}".format(os.path.basename(binary), name, hash)


def save_desc_for_later(signal, frame):
    if descFile is not None:
        pickle.dump(descMap, descFile)
    exit(0)


def attempt_ctx(args):
    binary = args[0]
    pindir = args[1]
    tool = args[2]
    hash = args[3]
    loc = args[4]
    name = args[5]
    processedFile = args[6]

    cmd = [os.path.join(pindir, "pin"), "-t", tool, "-fuzz-count", "0",
           "-target", hex(loc), "-out", name + ".log", "-watchdog", watchdog,
           "-contexts", os.path.abspath(os.path.join(WORK_DIR, FIFO_PIPE_NAME)), "--", binary]

    try:
        id = unique_identification(binary, name, hash)
        temp_file = open(id, "w+")
        temp_file.close()
        message = "Testing {}.{} ({}) with hash {}...".format(binary, name, hex(loc), hash)
        fuzz_cmd = subprocess.run(cmd, capture_output=True, timeout=int(watchdog) / 1000 + 1, cwd=os.path.abspath(
            WORK_DIR))
        found = False
        if fuzz_cmd.returncode == 0:
            output = fuzz_cmd.stdout.split(b'\n')
            for line in output:
                try:
                    line = line.decode("utf-8")
                    if "Input Contexts Passed: 1" in line:
                        found = True
                        descMap_lock.acquire()
                        descMap[hash].append(os.path.basename(binary) + "." + name)
                        descMap_lock.release()
                        break
                except UnicodeDecodeError:
                    continue

        if found:
            message += "accepted!"
        else:
            message += "failed"

        print_lock.acquire()
        print(message)
        print(id, file=processedFile)
        print_lock.release()
    except subprocess.TimeoutExpired:
        pass
    except Exception as e:
        print_lock.acquire()
        print("General exception: {}".format(e))
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

    results = parser.parse_args()
    mapFile = open(results.map, "wb")

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

    if not os.path.exists(results.contexts):
        print("Could not find {}".format(results.contexts), file=sys.stderr)
        exit(1)

    if not os.path.exists(results.binaries):
        print("Could not find {}".format(results.binaries), file=sys.stderr)
        exit(1)

    with open(results.contexts, "r") as contexts:
        with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
            pool.map(read_contexts, contexts)

    print("Unique Hashes: {}".format(len(hashMap)))
    pickle.dump(hashMap, mapFile)

    signal.signal(signal.SIGTERM, save_desc_for_later)

    with open(results.binaries, "r") as binaries:
        for binary in binaries.readlines():
            binary = binary.strip()
            binary = os.path.abspath(binary)
            location_map = dict()

            print("Reading function locations for {}...".format(binary), end='')
            sys.stdout.flush()
            readelf_cmd = subprocess.run(['readelf', '-s', binary], capture_output=True)
            lines = readelf_cmd.stdout.split(b'\n')
            for line in lines:
                line = line.decode('utf-8')
                toks = line.split()
                if len(toks) > 4 and toks[3] == "FUNC":
                    loc = int(toks[1], 16)
                    name = toks[-1]
                    if results.target is None or int(results.target, 16) == loc:
                        location_map[loc] = name
            print("done")

            for hash, iovec in hashMap.items():
                descMap[hash] = list()
                ctxPath = os.path.join(WORK_DIR, FIFO_PIPE_NAME)
                if os.path.exists(ctxPath):
                    os.unlink(ctxPath)
                out_pipe = open(ctxPath, "wb")
                iovec.write_bin(out_pipe)
                out_pipe.close()

                args = list()
                for loc, name in location_map.items():
                    if unique_identification(binary, name, hash) in processedBinaries:
                        continue
                    args.append(
                        [binary, os.path.abspath(results.pindir), os.path.abspath(results.tool), hash, loc, name,
                         processedFile])

                if len(args) > 0:
                    with futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                        try:
                            pool.map(attempt_ctx, args)
                        except KeyboardInterrupt:
                            save_desc_for_later(signal.SIGTERM, None)

    pickle.dump(descMap, descFile)
    processedFile.close()
    for hash, funcs in descMap.items():
        print("{}: {}".format(hash, funcs))


if __name__ == "__main__":
    main()
