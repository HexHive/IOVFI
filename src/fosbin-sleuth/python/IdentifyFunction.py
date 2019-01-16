#!/usr/bin/python3

import argparse
import os
import sys
import pickle
from contexts import IOVec, FBDecisionTree, binaryutils
import subprocess

CTX_FILENAME = "input.ctx"
WORK_DIR = "_work"
WATCHDOG_MS = 5000


def attempt_ctx(iovec, pindir, tool, loc, name, watchdog, binary, hash):
    fullPath = os.path.abspath(os.path.join(WORK_DIR, CTX_FILENAME))
    ctx_file = open(fullPath, "wb")
    iovec.write_bin(ctx_file)
    ctx_file.close()
    cmd = [os.path.join(pindir, "pin"), "-t", tool, "-fuzz-count", "0",
           "-target", hex(loc), "-out", name + ".log", "-watchdog", str(watchdog),
           "-contexts", fullPath, "--", binary]

    try:
        print("Testing {}.{} ({}) with hash {}...".format(binary, name, loc, hash), end='')
        fuzz_cmd = subprocess.run(cmd, capture_output=True, timeout=watchdog / 1000 + 1, cwd=os.path.abspath(
            WORK_DIR))
        accepted = fuzz_cmd.returncode == 0

        if accepted:
            print("accepted!")
            return True
        else:
            print("failed")
            return False
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        return False
    finally:
        if os.path.exists(fullPath):
            os.unlink(fullPath)


def check_inputs(argparser):
    if not os.path.exists(argparser.tree):
        print("Could not find {}".format(argparser.tree), file=sys.stderr)
    exit(1)

    if not os.path.exists(argparser.map):
        print("Could not find {}".format(argparser.map), file=sys.stderr)
        exit(1)

    if not os.path.exists(argparser.out):
        print("Could not find {}".format(argparser.out), file=sys.stderr)
        exit(1)

    if not os.path.exists(argparser.binary):
        print("Could not find {}".format(argparser.binary), file=sys.stderr)
        exit(1)


def main():
    parser = argparse.ArgumentParser(description="IdentifyFunction")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default="tree.bin")
    parser.add_argument('-m', '--map', help="Map of hashes and contexts", default="hash.map")
    parser.add_argument('-o', '--out', help="Output of which contexts execute with which functions", default="out.desc")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-target", help="Address to target single function")
    parser.add_argument("-b", "--binary", help="Binary to identify", required=True)
    results = parser.parse_args()

    check_inputs(results)

    treeFile = open(results.tree, "rb")
    fbDtree = pickle.load(treeFile)
    treeFile.close()

    hashFile = open(results.map, "rb")
    hashMap = pickle.load(hashFile)
    hashFile.close()

    descFile = open(results.out, "rb")
    descMap = pickle.load(descFile)
    descFile.close()

    dtree = fbDtree.dtree
    classifier = dtree.tree_
    idx = 0

    location_map = binaryutils.find_funcs(results.binary, results.target)

    for loc, name in location_map.items():
        while idx < classifier.node_count:
            if classifier.children_left[idx] == classifier.children_right[idx]:
                print("Reached leaf")
                print(dtree.classes_[idx])
                break

            hash = fbDtree.labelEncoder.inverse_transform([classifier.feature[idx]])[0]
            iovec = hashMap[hash]
            if attempt_ctx(iovec, results.pindir, loc, name, WATCHDOG_MS, results.binary, hash):
                idx = classifier.children_left[idx]
            else:
                idx = classifier.children_right[idx]


if __name__ == "__main__":
    main()
