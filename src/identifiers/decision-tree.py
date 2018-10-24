#!/usr/bin/python3

import numpy as np
import pandas as pd
import sys
import os
import struct
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score
from sklearn import tree
import binascii

training_data = {}


def float_parser(value):
    if value is None:
        print("None")
        return value

    if "0x" in value:
        ret = struct.unpack('d', binascii.unhexlify(value[2:]))
    elif "?" in value:
        ret = float('nan')
    else:
        ret = float(value)

    return ret


def main():
    if len(sys.argv) != 2:
        print("usage: decision-tree.py /path/to/training/data.csv")
        exit(1)

    training_data = pd.read_csv(sys.argv[1], error_bad_lines=False, warn_bad_lines=True,
                                skipinitialspace=True,
                                converters={"return": float_parser, "arg0": float_parser, "arg1": float_parser,
                                            "arg2": float_parser, "arg3": float_parser, "arg4": float_parser,
                                            "arg5": float_parser, "arg6": float_parser, "arg7": float_parser,
                                            "arg8": float_parser, "arg9": float_parser, "arg10": float_parser,
                                            "arg11": float_parser})
    print("Training Data Length: {}".format(len(training_data)))
    print("Training Data Shape: {}".format(training_data.shape))
    print("Training Data Head:\n{}".format(training_data.head()))

    feature_set = training_data.values[:, 1:4]
    #print("Feature Set: ", feature_set)
    outcome_set = training_data.values[:, 0]
    #print("Outcome Set: ", outcome_set)

    feature_train, feature_test, outcome_train, outcome_test = train_test_split(feature_set, outcome_set, test_size=0.3)

    clf_gini = DecisionTreeClassifier(criterion="gini")
    clf_gini.fit(feature_train, outcome_train)

    clf_entropy = DecisionTreeClassifier(criterion="entropy")
    clf_entropy.fit(feature_train, outcome_train)

    gini_pred = clf_gini.predict(feature_test)
    entropy_pred = clf_entropy.predict(feature_test)

    print("Gini accuracy = {}\tEntropy accuracy = {}".format(accuracy_score(outcome_test, gini_pred) * 100,
                                                             accuracy_score(outcome_test, entropy_pred) * 100))

    tree.export_graphviz(clf_gini, 'gini.dot')
    tree.export_graphviz(clf_entropy, 'entropy.dot')


if __name__ == "__main__":
    main()
