#!/usr/bin/python3

import r2pipe
import os
import sys
import subprocess
import argparse

fuzz_count = "5"


def usage():
    print("{} /path/to/pin/dir /path/to/fosbin-zergling.so /path/to/application [/path/to/application...]".format(
        "fuzz-applications.py"))
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Generate input/output vectors")
    parser.add_argument("-pindir", help="/path/to/pin/dir")
    parser.add_argument("-tool", help="/path/to/pintool")
    parser.add_argument("-bin", help="/path/to/target/application")
    parser.add_argument("-ignore", help="/path/to/ignored/functions")
    parser.add_argument("-ld", help="/path/to/fb-load")

    results = parser.parse_args()
    if os.path.splitext(results.bin)[1] == ".so" and (results.ld is None or results.ld == ""):
        parser.print_help()
        exit(1)

    env_vars = dict()
    r2 = r2pipe.open(results.bin)
    r2.cmd('aaa')
    func_count = 0
    failed_count = 0
    success_count = 0
    ignored_funcs = set()
    if results.ignore is not None:
        with open(results.ignore) as f:
            for line in f.readlines():
                line = line.strip()
                ignored_funcs.add(line)

    for func in r2.cmdj("aflj"):
        func_count += 1

        try:
            func_name = func['name'][len("sym."):]
            if func_name in ignored_funcs:
                continue

            if os.path.splitext(results.bin)[1] == ".so":
                cmd = [os.path.join(results.pindir, "pin"), "-t", results.tool, "-fuzz-count", fuzz_count,
                       "-shared-func", func_name, "-out", func_name + ".log", "--", results.ld, results.bin]
            else:
                cmd = [os.path.join(results.pindir, "pin"), "-t", results.tool, "-fuzz-count", fuzz_count,
                       "-target", hex(func['offset']), "-error_file", func['offset'] + ".log", "--", results.bin]
            print("Running {}".format(" ".join(cmd)))
            returnCode = subprocess.run(cmd, env=env_vars, timeout=10)
            if returnCode.returncode != 0:
                failed_count += 1
            else:
                success_count += 1
        except subprocess.TimeoutExpired:
            failed_count += 1
            continue
        except Exception as e:
            print("Error for {}:{} : {}".format(results.bin, func['name'], e), file=sys.stderr)
            failed_count += 1
            continue

        print("Finished {}".format(func['name']))

    print("{} has {} functions".format(results.bin, func_count))
    print("Fuzzable functions: {}".format(success_count))
    print("Failed functions: {} ({})".format(failed_count, failed_count / (failed_count + success_count)))
    r2.quit()


if __name__ == "__main__":
    main()
