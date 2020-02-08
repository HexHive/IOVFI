#!/usr/bin/python3

import argparse
import os
import pickle
import statistics
import sys

import contexts.treeutils as tu


def main():
    parser = argparse.ArgumentParser(description=os.path.basename(sys.argv[0]))
    parser.add_argument('-o', '--out', help="/path/to/output/function/coverage/map", default="cov.map")
    parser.add_argument('-t', '--tree', help='/path/to/tree.bin', default='tree.bin')
    parser.add_argument('-s', '--hash', help='/path/to/hash.map', default='hash.map')
    parser.add_argument('-d', '--descs', help='/path/to/out.desc', default='out.desc')

    results = parser.parse_args()

    with open(results.tree, 'rb') as f:
        dtree = pickle.load(f)

    with open(results.hash, 'rb') as f:
        hashmap = pickle.load(f)

    with open(results.descs, 'rb') as f:
        func_descs = pickle.load(f)

    ec_coverage = dict()
    for h, fds in func_descs.items():
        for (func_desc, coverage) in fds:
            if func_desc not in ec_coverage:
                ec_coverage[func_desc] = dict()
            ec_coverage[func_desc][h] = coverage

    path_coverages = dict()
    for func_desc, coverages in ec_coverage.items():
        tree_path = tu.get_tree_path(dtree, func_desc.name)
        path_coverages[func_desc] = list()
        for idx in tree_path:
            iovec = dtree.get_iovec(idx)
            if iovec is not None:
                h = hash(iovec)
                if h in ec_coverage[func_desc]:
                    path_coverages[func_desc].append(ec_coverage[func_desc][h])

    for func_desc, path_coverage in path_coverages.items():
        if len(path_coverage) > 0:
            print("{}: {}".format(func_desc.name, statistics.mean(path_coverage)))
        else:
            print("{}: ERROR".format(func_desc.name))


if __name__ == "__main__":
    main()
