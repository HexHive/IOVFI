#!/usr/bin/python3

import argparse
import pickle
import contexts.treeutils as tu


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/list", default="guesses.txt")
    parser.add_argument("-n", dest="out_count", help="Number of mislabels to output", type=int, default=10)

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    mislabels = dict()

    with open(args.guesses, "r") as guessList:
        for guessLine in guessList.readlines():
            guessLine = guessLine.strip()
            with open(guessLine, "rb") as guessFile:
                guesses = pickle.load(guessFile)

            _, _, incorrect = tu.get_evaluation(dtree, guesses)
            for mislabel in incorrect:
                if mislabel not in mislabels:
                    mislabels[mislabel] = 0
                mislabels[mislabel] += 1

    sorted_list = sorted(mislabels.items(), key=lambda item: item[1], reverse=True)
    for idx in range(0, min(len(sorted_list), args.out_count)):
        print("{}: {}".format(sorted_list[idx][0], sorted_list[idx][1]))


if __name__ == "__main__":
    main()
