#!/usr/bin/python3

import argparse
import pickle
import statistics
import sys


def lcs(a, b):
    # generate matrix of length of longest common subsequence for substrings of both words
    lengths = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if x == y:
                lengths[i + 1][j + 1] = lengths[i][j] + 1
            else:
                lengths[i + 1][j + 1] = max(lengths[i + 1][j], lengths[i][j + 1])

    # read a substring from the matrix
    result = ''
    j = len(b)
    for i in range(len(a) + 1):
        if lengths[i][j] != lengths[i - 1][j]:
            result += a[i - 1]

    return result


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/list", default="guesses.txt")
    parser.add_argument("-lcs", help="Longest common subsequence length",
                        type=float, default=.9)

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    precisions = dict()
    recalls = dict()
    fscores = dict()

    true_positives = dict()
    true_negatives = dict()
    false_positives = dict()
    false_negatives = dict()

    with open(args.guesses, "r") as guessList:
        for guessLine in guessList.readlines():
            guessLine = guessLine.strip()
            print("Computing fscore for {}".format(guessLine))
            with open(guessLine, "rb") as guessFile:
                guesses = pickle.load(guessFile)

            true_pos = list()
            true_neg = list()
            false_pos = list()
            false_neg = list()

            for func_desc, guess in guesses.items():
                equiv_classes = dtree.get_equiv_classes(guess)
                if equiv_classes is None:
                    found = False
                    for pres_func_desc in dtree.get_func_descs():
                        if pres_func_desc.name == func_desc.name:
                            found = True
                            break
                    if found:
                        false_neg.append(func_desc)
                        false_pos.append(func_desc)
                    else:
                        true_neg.append(func_desc)
                else:
                    found = False
                    for equiv_class in equiv_classes:
                       # subseq = lcs(equiv_class.name, func_desc.name)
                        if func_desc.name == equiv_class.name: 
                       # if float(len(subseq)) >= float(len(func_desc.name)) * args.lcs:
                       #     print("{}, {}: {}".format(equiv_class.name, func_desc.name, subseq))
                            found = True
                            break
                    if found:
                        true_pos.append(func_desc)
                    else:
                        false_pos.append(func_desc)
                        false_neg.append(func_desc)

            fscore = 0
            precision = 0
            recall = 0
            if len(true_pos) != 0 and len(false_pos) != 0:
                precision = len(true_pos) / (len(true_pos) + len(false_pos))
            else:
                print("Could not compute precision for {}".format(guessLine), file=sys.stderr)
                continue

            if len(true_pos) != 0 and len(false_neg) != 0:
                recall = len(true_pos) / (len(true_pos) + len(false_neg))
            else:
                print("Could not compute recall for {}".format(guessLine), file=sys.stderr)
                continue
            fscore = 2 * precision * recall / (precision + recall)
            precisions[guessLine] = precision
            recalls[guessLine] = recall
            fscores[guessLine] = fscore
            true_positives[guessLine] = true_pos
            true_negatives[guessLine] = true_neg
            false_positives[guessLine] = false_pos
            false_negatives[guessLine] = false_neg

    fscore_tmp = list()
    precision_tmp = list()
    recall_tmp = list()
    true_pos_tmp = list()
    true_neg_tmp = list()
    false_pos_tmp = list()
    false_neg_tmp = list()

    for guessLoc, fscore in fscores.items():
        fscore_tmp.append(fscore)

    for guessLoc, precision in precisions.items():
        precision_tmp.append(precision)

    for guessLoc, recall in recalls.items():
        recall_tmp.append(recall)

    for val in true_positives.values():
        true_pos_tmp.append(len(val))

    for val in true_negatives.values():
        true_neg_tmp.append(len(val))

    for val in false_positives.values():
        false_pos_tmp.append(len(val))

    for val in false_negatives.values():
        false_neg_tmp.append(len(val))

    if len(fscore_tmp) > 1:
        print("Average F-score of {} tests: {} +- {}".format(len(fscore_tmp), statistics.mean(fscore_tmp),
                                                             statistics.stdev(fscore_tmp)))
    else:
        print("Average F-score of {} tests: {} +- {}".format(len(fscore_tmp), statistics.mean(fscore_tmp), 0))

    if len(precision_tmp) > 1:
        print("Average precision of {} tests: {} +- {}".format(len(precision_tmp),
                                                               statistics.mean(precision_tmp),
                                                               statistics.stdev(precision_tmp)))
    else:
        print("Average precision of {} tests: {} +- {}".format(len(precision_tmp),
                                                               statistics.mean(precision_tmp), 0))

    if len(recall_tmp) > 1:
        print("Average recall of {} tests: {} +- {}".format(len(recall_tmp),
                                                            statistics.mean(recall_tmp),
                                                            statistics.stdev(recall_tmp)))
    else:
        print("Average recall of {} tests: {} +- {}".format(len(recall_tmp),
                                                            statistics.mean(recall_tmp), 0))

    if len(true_pos_tmp) > 1:
        print("Average true pos:  {} +- {}".format(statistics.mean(true_pos_tmp),
                                                   statistics.stdev(true_pos_tmp)))
    else:
        print("Average true pos:  {} +- {}".format(statistics.mean(true_pos_tmp), 0))

    if len(false_pos_tmp) > 1:
        print("Average false pos: {} +- {}".format(statistics.mean(false_pos_tmp),
                                                   statistics.stdev(false_pos_tmp)))
    else:
        print("Average false pos: {} +- {}".format(statistics.mean(false_pos_tmp), 0))

    if len(true_neg_tmp) > 1:
        print("Average true neg:  {} +- {}".format(statistics.mean(true_neg_tmp),
                                                   statistics.stdev(true_neg_tmp)))
    else:
        print("Average true neg:  {} +- {}".format(statistics.mean(true_neg_tmp), 0))

    if len(false_neg_tmp) > 1:
        print("Average false neg: {} +- {}".format(statistics.mean(false_neg_tmp),
                                                   statistics.stdev(false_neg_tmp)))
    else:
        print("Average false neg: {} +- {}".format(statistics.mean(false_neg_tmp), 0))


if __name__ == "__main__":
    main()
