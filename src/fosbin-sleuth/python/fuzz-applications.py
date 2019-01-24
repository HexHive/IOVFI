#!/usr/bin/python3

import os
import sys
import subprocess
import argparse
from contexts import binaryutils
import logging

fuzz_count = "5"
watchdog = 5 * 1000
work_dir = "contexts"

log = logging.getLogger(binaryutils.LOGGER_NAME)

def main():
    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-pindir", help="/path/to/pin/dir", required=True)
    parser.add_argument("-tool", help="/path/to/pintool", required=True)
    parser.add_argument("-bin", help="/path/to/target/application", required=True)
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")
    parser.add_argument("-funcs", help="/path/to/file/with/func/names")

    results = parser.parse_args()
    if os.path.splitext(results.bin)[1] == ".so" and (results.ld is None or results.ld == ""):
        parser.print_help()
        exit(1)

    log.setLevel(logging.INFO)
    func_count = 0
    failed_count = 0
    success_count = 0
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

    for location, func_name in locationMap.items():
        func_count += 1
        if '@' in func_name:
            func_name = func_name[:func_name.find("@")]

        try:
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
            log.info("Running {}".format(" ".join(cmd)))
            returnCode = subprocess.run(cmd, timeout=watchdog / 1000 + 1, cwd=os.path.abspath(work_dir))
            if returnCode.returncode != 0:
                failed_count += 1
            else:
                success_count += 1
        except subprocess.TimeoutExpired:
            failed_count += 1
            continue
        except Exception as e:
            log.error("Error for {}:{} : {}".format(results.bin, func_name, e))
            failed_count += 1
            continue

        log.info("Finished {}".format(func_name))

    log.info("{} has {} functions".format(results.bin, func_count))
    log.info("Fuzzable functions: {}".format(success_count))
    if failed_count + success_count > 0:
        log.info("Failed functions: {} ({})".format(failed_count, failed_count / (failed_count + success_count)))


if __name__ == "__main__":
    main()
