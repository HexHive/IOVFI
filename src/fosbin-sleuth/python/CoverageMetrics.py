#!/usr/bin/python3

import argparse
import os
import pickle
import sys

import matplotlib.pyplot as plt

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
        for func_desc, coverage in fds.items():
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
                    path_coverages[func_desc] = ec_coverage[func_desc][h]

    all_coverage = list()
    low_coverage = list()

    for func_desc, path_coverage in path_coverages.items():
        if len(path_coverage) > 0:
            all_executed = list()
            all_instructions = list()
            for (executedInstructions, totalInstructions) in path_coverage:
                all_executed.append(executedInstructions)
                all_instructions.append(totalInstructions)
            coverage_percent = sum(all_executed) / sum(all_instructions)
            all_coverage.append(coverage_percent)
            if coverage_percent < 0.5:
                low_coverage.append((func_desc, coverage_percent))

    if len(all_coverage) > 0:
        all_coverage.sort()
        plt.hist(all_coverage, 20, facecolor='blue', alpha=0.5)
        plt.savefig('cov.png')
    else:
        print("No coverage data available")

    ecs = dtree.get_all_equiv_classes()
    low_coverage.sort(key=lambda ent: ent[1])
    index_count = dict()
    for ent in low_coverage:
        for ec in ecs:
            for fd in ec:
                if fd[0].name == ent[0].name:
                    print("{}: {} ({})".format(ent[0].name, ent[1], ecs.index(ec)))
                    if ecs.index(ec) not in index_count:
                        index_count[ecs.index(ec)] = 1
                    else:
                        index_count[ecs.index(ec)] += 1
                    break

    for idx, count in index_count.items():
        print("{}: {} ({})".format(idx, count, count / len(low_coverage)))


if __name__ == "__main__":
    main()
