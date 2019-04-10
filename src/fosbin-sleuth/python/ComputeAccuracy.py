#!/usr/bin/python3

import argparse
import pickle
import statistics
import contexts.treeutils as tu


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/list", default="guesses.txt")

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    accuracies = list()

    with open(args.guesses, "r") as guessList:
        for guessLine in guessList.readlines():
            guessLine = guessLine.strip()
            print("Computing accuracy for {}".format(guessLine))
            with open(guessLine, "rb") as guessFile:
                guesses = pickle.load(guessFile)

            true_pos, true_neg, incorrect = tu.get_evaluation(dtree, guesses)
            accuracy = (len(true_pos) + len(true_neg)) / (len(true_pos) + len(true_neg) + len(incorrect) + len(
                incorrect))
            accuracies.append(accuracy)

    if len(accuracies) > 1:
        avg = statistics.mean(accuracies)
        stddev = statistics.stdev(accuracies)
    elif len(accuracies) == 1:
        avg = accuracies[0]
        stddev = 0
    else:
        raise AssertionError("No guesses provided")

    print("Average Accuracy: {} +- {}".format(avg, stddev))


if __name__ == "__main__":
    main()
