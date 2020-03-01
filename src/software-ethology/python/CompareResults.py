#!/usr/bin/python3

import pickle
import argparse
import os
import sys


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", nargs="+", help="/path/to/guess/file1 /path/to/guess/file2",
                        required=True)

    args = parser.parse_args()
    if len(args.guesses) != 2:
        print("Supply only two sets of guesses", file=sys.stderr)
        exit(1)

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    collected_guesses = dict()

    for guessfile in args.guesses:
        with open(guessfile, "r") as guessList:
            for guessLine in guessList.readlines():
                guessLine = os.path.abspath(guessLine.strip())
                print("Computing classifications for {}".format(guessLine))
                with open(guessLine, "rb") as guessFile:
                    guesses = pickle.load(guessFile)

                for func_desc, guess in guesses.items():
                    if func_desc.name not in collected_guesses:
                        collected_guesses[func_desc.name] = dict()
                    if guess not in collected_guesses[func_desc.name]:
                        collected_guesses[func_desc.name][guess] = list()

                    collected_guesses[func_desc.name][guess].append(guessLine)

    for name, guesses in collected_guesses.items():
        if len(guesses) > 1:
            print()
            print("{}:".format(name))
            for guess, guessLines in guesses.items():
                for file in guessLines:
                    print("\t{}".format(file))
                equiv_classes = dtree.get_equiv_classes(guess)
                if equiv_classes is None:
                    print("\t\tUnknown")
                else:
                    for equiv_class in equiv_classes:
                        print("\t\t{}".format(equiv_class.name))


if __name__ == "__main__":
    main()
