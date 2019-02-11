#!/usr/bin/python3

import os
import pickle
import argparse
from pathlib import Path
from contexts.FBDecisionTree import FBDecisionTree
import contexts.FBLogging.logger as logger


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-prefix", default="", help="Guess entry prefix")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", action="append", nargs="+", help="/path/to/guess/dir")

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        tree = pickle.load(treefile)

    successful_guesses = list()
    failed_guesses = list()
    unknown_guesses = list()
    failed_set = dict()

    for guess_path_list in args.guesses:
        for guess_path in guess_path_list:
            pathlist = Path(guess_path).glob("**/*.bin")
            for path in pathlist:
                path = os.path.abspath(path)
                logger.info("Reading {}".format(path))
                with open(path, "rb") as guessfile:
                    guessmap = pickle.load(guessfile)
                    for key, guess_idx in guessmap.items():
                        if guess_idx == FBDecisionTree.UNKNOWN_FUNC:
                            unknown_guesses.append(key)
                            continue

                        guesses = tree.get_equiv_classes(guess_idx)
                        found = False
                        for guess in guesses:
                            guess = guess[len(args.prefix):]
                            if key.find(guess) >= 0:
                                successful_guesses.append(key)
                                found = True
                                break

                        if not found:
                            failed_guesses.append(key)
                            if key not in failed_set:
                                failed_set[key] = set()
                            for guess in guesses:
                                failed_set[key].add(guess)

    for key, failed_guess in failed_set.items():
        logger.info("{}: {}".format(key, failed_guess))

    logger.info("Successful guesses:  {} ({})".format(len(successful_guesses), len(successful_guesses) / (
                len(successful_guesses) + len(failed_guesses))))
    logger.info("Failed guesses:      {} ({})".format(len(failed_guesses),
                                                      len(failed_guesses) / (len(successful_guesses) + len(failed_guesses))))
    logger.info("Unknown guesses:     {}".format(len(unknown_guesses)))


if __name__ == "__main__":
    main()
