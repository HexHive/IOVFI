#!/bin/python3

import os
import pickle
import statistics
import sys

BIN_COUNT = 10


def main():
    if len(sys.argv) != 2:
        print("%s /path/to/tree.bin" % (os.path.basename(sys.argv[0])))
        exit(1)
    with open(sys.argv[1], 'rb') as f:
        tree = pickle.load(f)

    equiv_classes = tree.get_all_equiv_classes()

    bins = dict()
    for bin_idx in range(1, BIN_COUNT + 1):
        bins[bin_idx] = 0

    max_ec_len = -1
    max_ec = None
    ec_sizes = list()
    for ec in equiv_classes:
        ec_sizes.append(len(ec))

        if len(ec) >= BIN_COUNT:
            bins[BIN_COUNT] += 1
        else:
            bins[len(ec)] += 1

        if len(ec) > max_ec_len:
            max_ec_len = len(ec)
            max_ec = ec

    print("Max EC:    %d" % max_ec_len)
    print("N:         %d" % (sum(ec_sizes)))
    print("N_bar:     %f +- %f" % (statistics.mean(ec_sizes), statistics.stdev(ec_sizes)))
    print("Med N_bar: %d" % (statistics.mean(ec_sizes)))
    for bin_idx in range(1, BIN_COUNT + 1):
        print("%d: %d" % (bin_idx, bins[bin_idx]))

    names = list()
    for ec in max_ec:
        names.append(ec.name)
    names.sort()
    for name in names:
        print(name)


if __name__ == "__main__":
    main()
