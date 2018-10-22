#!/usr/bin/python3

import json
import sys

functions = []

def main():
    if len(sys.argv) < 2:
        print("gen-csv.py /path/to/json ...")
        exit(1)

    max_args = -1

    for i in range(1, len(sys.argv)):
        with open(sys.argv[i], "r") as f:
            for line in f.readlines():
                line = line.strip()
                if line.find("\"function\":") >= 0:
                    if line[len(line) - 1] == ',':
                        line = line[:-1]
                    func = json.loads(line)['function']
                    if len(func['args']) > max_args:
                        max_args = len(func['args'])
                    functions.append(func)

    print("return, arg_count", end="")
    if max_args > 0:
        print(", ", end="")

    for i in range(max_args):
        print("arg{}".format(i), end="")
        if i < max_args - 1:
            print(", ", end="")

    print("")

    for func in functions:
        print("{}, {}".format(func['return']['value'], len(func['args'])), end="")
        if max_args > 0:
            print(", ", end = "")
        for i in range(max_args):
            if i < len(func['args']):
                print(func['args'][i]['value'], end="")
            else:
                print("?", end="")

            if i < max_args - 1:
                print(", ", end="")
        print("")

if __name__ == "__main__":
    main()
