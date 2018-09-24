#!/usr/bin/python3

import sys


def usage():
    print("usage: {} /path/to/results /path/to/mapping".format(sys.argv[0]))

def main():
    if len(sys.argv) != 3:
        usage()
        exit(1)

    address_map = {}

    with open(sys.argv[1], "r") as results:
        for result in results.readlines():
            result = result.strip()
            index = result.find(":")
            if index >= 0:
                address = result[:index]
                signature = result[index + 2:]
                address_map[address] = signature

    with open(sys.argv[2], "r") as mappings:
        for mapping in mappings.readlines():
            mapping = mapping.strip()
            index = mapping.find("=")
            if index >= 0:
                address = mapping[:index].strip()
                name = mapping[index + 1:].strip()
                if address not in address_map:
                    print("{}".format(name))


if __name__ == "__main__":
    main()