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
    if not os.path.exists(WORK_DIR):
        os.mkdir(WORK_DIR)

    ctx_file = open(fullPath, "wb+")
    iovec.write_bin(ctx_file)
    ctx_file.close()
    cmd = [os.path.abspath(os.path.join(pindir, "pin")), "-t", os.path.abspath(tool), "-fuzz-count", "0",
           "-target", hex(loc), "-out", name + ".log", "-watchdog", str(watchdog),
           "-contexts", fullPath, "--", os.path.abspath(binary)]

    accepted = False
    try:
        print("Testing {}.{} ({}) with hash {}...".format(os.path.basename(binary), name, hex(loc), hash), end='')
        sys.stdout.flush()
        fuzz_cmd = subprocess.run(cmd, timeout=watchdog / 1000 + 1, cwd=os.path.abspath(WORK_DIR))
        accepted = (fuzz_cmd.returncode == 0)

        if accepted:
            return True
        else:
            return False
    except subprocess.TimeoutExpired:
        print("Timeout")
        return False
    except Exception as e:
        print("General exception: {}".format(e))
        return False
    finally:
        if not accepted:
            print("failed")
        else:
            print("accepted!")

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

    print("Checking inputs...", end='')
    check_inputs(results)
    print("done!")

    print("Parsing tree at {}...".format(results.tree), end='')
    treeFile = open(results.tree, "rb")
    fbDtree = pickle.load(treeFile)
    treeFile.close()
    print("done!")

    print("Parsing hash map at {}...".format(results.map), end='')
    hashFile = open(results.map, "rb")
    hashMap = pickle.load(hashFile)
    hashFile.close()
    print("done!")

    print("Parsing descMap at {}...".format(results.out), end='')
    descFile = open(results.out, "rb")
    descMap = pickle.load(descFile)
    descFile.close()
    print("done!")

    dtree = fbDtree.dtree
    classifier = dtree.tree_

    print("Finding functions in {}...".format(results.binary), end='')
    location_map = binaryutils.find_funcs(results.binary, results.target)
    print("done!")
    print("Found {} functions".format(len(location_map)))

    for loc, name in location_map.items():
        idx = 0
        while idx < classifier.node_count:
            if classifier.children_left[idx] == classifier.children_right[idx]:
                func_guesses = set()
                for i in range(len(classifier.value[idx][0])):
                    if dtree.tree_.value[idx][0][i]:
                        func_guesses.add(dtree.classes_[i])
                print("{}.{}: {}".format(os.path.basename(results.binary), name, func_guesses))
                break

            hash = fbDtree.labelEncoder.inverse_transform([classifier.feature[idx]])[0]
            iovec = hashMap[hash]
            if attempt_ctx(iovec, results.pindir, results.tool, loc, name, WATCHDOG_MS, results.binary, hash):
                idx = classifier.children_right[idx]
            else:
                idx = classifier.children_left[idx]


if __name__ == "__main__":
    main()
