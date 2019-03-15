#!/usr/bin/python3

import pickle
import argparse
import statistics


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/dir", default="guesses.bin")

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
                        if pres_func_desc.name == func_desc:
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
                        if equiv_class.name == func_desc.name:
                            found = True
                            break

                    if found:
                        true_pos.append(func_desc)
                    else:
                        bad_guesses = set()
                        for equiv_class in equiv_classes:
                            bad_guesses.add(str(equiv_class))
                        # print("{}: {}\n".format(func_desc.name, " ".join(bad_guesses)))
                        false_pos.append(func_desc)
                        false_neg.append(func_desc)

            precision = len(true_pos) / (len(true_pos) + len(false_pos))
            recall = len(true_pos) / (len(true_pos) + len(false_neg))
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

    print("Average F-score of {} tests: {} +- {}".format(len(fscore_tmp), statistics.mean(fscore_tmp),
                                                         statistics.stdev(fscore_tmp)))
    print("Average precision of {} tests: {} +- {}".format(len(precision_tmp),
                                                           statistics.mean(precision_tmp),
                                                           statistics.stdev(precision_tmp)))
    print("Average recall of {} tests: {} +- {}".format(len(recall_tmp),
                                                        statistics.mean(recall_tmp),
                                                        statistics.stdev(recall_tmp)))
    print("Average true pos:  {} +- {}".format(statistics.mean(true_pos_tmp),
                                               statistics.stdev(true_pos_tmp)))
    print("Average false pos: {} +- {}".format(statistics.mean(false_pos_tmp),
                                               statistics.stdev(false_pos_tmp)))
    print("Average true neg:  {} +- {}".format(statistics.mean(true_neg_tmp),
                                               statistics.stdev(true_neg_tmp)))
    print("Average false neg: {} +- {}".format(statistics.mean(false_neg_tmp),
                                               statistics.stdev(false_neg_tmp)))


if __name__ == "__main__":
    main()
