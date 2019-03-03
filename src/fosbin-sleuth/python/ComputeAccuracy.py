#!/usr/bin/python3

import pickle
import argparse


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/dir", default="guesses.bin")

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    with open(args.guesses, "rb") as guessFile:
        guesses = pickle.load(guessFile)

    true_pos = list()
    true_neg = list()
    false_pos = list()
    false_neg = list()

    for func_desc, guess in guesses.items():
        equiv_classes = dtree.get_equiv_class(guess)
        if equiv_classes is None:
            found = False
            for pres_func_desc in dtree.funcDescs:
                if pres_func_desc.name == func_desc:
                    found = True
                    break
            if found:
                false_neg.append(func_desc)
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
                false_pos.append(func_desc)

    print("True pos:  {}".format(len(true_pos)))
    print("True neg:  {}".format(len(true_neg)))
    print("False pos: {}".format(len(false_pos)))
    print("False neg: {}".format(len(false_neg)))

    precision = len(true_pos) / (len(true_pos) + len(false_pos))
    recall = len(true_pos) / (len(true_pos) + len(false_neg))
    fscore = 2 * precision * recall / (precision + recall)

    print("Precision: {}".format(precision))
    print("Recall:    {}".format(recall))
    print("FScore:    {}".format(fscore))


if __name__ == "__main__":
    main()
