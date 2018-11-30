#!/usr/bin/python3

import sys
import os
import re


def usage():
    print("usage: {} /path/to/fosbin/flop/log".format(sys.argv[0]))


def main():
    if len(sys.argv) != 2:
        usage()
        exit(1)

    functions = dict()
    found_funcs = dict()
    unconfirmed_funcs = set()

    function_regex = re.compile(".*(0x[0-9A-Fa-f]+)=([a-zA-Z0-9_]+)")
    found_regex = re.compile(".*FOUND (0x[0-9A-Fa-f]+) to be ([a-zA-Z0-9_]+)")
    unconfirmed_regex = re.compile(".*Leaf at ([0-9A-Fa-f]+) unconfirmed")

    with open(sys.argv[1], "r", errors='ignore') as lines:
        for line in lines.readlines():
            function_match = function_regex.match(line)
            if function_match:
                functions[function_match.group(1).strip()] = function_match.group(2).strip()
                continue

            found_match = found_regex.match(line)
            if found_match:
                found_funcs[found_match.group(1).strip()] = found_match.group(2).strip()
                continue

            unconfirmed_match = unconfirmed_regex.match(line)
            if unconfirmed_match:
                unconfirmed_funcs.add("0x" + unconfirmed_match.group(1))
                continue

    total_tested_functions = len(found_funcs) + len(unconfirmed_funcs)
    total_mislabeled_functions = 0
    total_correct_functions = 0
    total_unconfirmed_functions = len(unconfirmed_funcs)
    for addr, guess in found_funcs.items():
        if guess != functions[addr]:
            print("Function at {} ({}) was mislabeled as {}".format(addr, functions[addr], guess))
            total_mislabeled_functions += 1
            continue
        else:
            total_correct_functions += 1

    for addr in unconfirmed_funcs:
        print("Function {} ({}) unconfirmed".format(addr, functions[addr]))

    print("=============== Summary ==================")
    print("Total Tested Functions: {}".format(total_tested_functions))
    print("Total Correct Functions: {} ({}%)".format(total_correct_functions, total_correct_functions /
                                                     total_tested_functions * 100))
    print("Total Mislabeled Functions: {} ({}%)".format(total_mislabeled_functions, total_mislabeled_functions /
                                                        total_tested_functions * 100))
    print("Total Unconfirmed Functions: {} ({}%)".format(total_unconfirmed_functions, total_unconfirmed_functions /
                                                         total_tested_functions * 100))

if __name__ == "__main__":
    main()
