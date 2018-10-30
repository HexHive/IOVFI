#!/usr/bin/python3

import argparse
from sklearn import tree
from sklearn.feature_extraction import DictVectorizer
import pandas as pd
from collections import defaultdict
import sys


def parser(value):
    if value is None or value == '?':
        return None

    return str(value)


def load_file(fname):
    print("parsing CSV...", end="")
    sys.stdout.flush()
    data = pd.read_csv(fname, error_bad_lines=False, warn_bad_lines=True,
                       converters={"return": parser, "arg0": parser, "arg1": parser,
                                   "arg2": parser, "arg3": parser, "arg4": parser,
                                   "arg5": parser, "arg6": parser, "arg7": parser,
                                   "arg8": parser, "arg9": parser, "arg10": parser,
                                   "arg11": parser})
    print("done!")

    examples = data.values[:, 1:4]
    label = data.values[:, 0]

    fvdicts = defaultdict(dict)

    for idx in range(len(label)):
        fv = tuple(examples[idx])
        fvdicts[label[idx]][fv] = 1

    dual_labels = list()
    dual_features = list()

    for key in fvdicts:
        dual_labels.append(key)
        dual_features.append(fvdicts[key])

    dv = DictVectorizer()
    X = dv.fit_transform(dual_features)

    dtree = tree.DecisionTreeClassifier(criterion="entropy")
    dtree.fit(X, dual_labels)

    tree.export_graphviz(dtree, out_file="dtree.dot")


if __name__ == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument("dataf", type=str, help="TODO")

    args = argp.parse_args()

    load_file(args.dataf)
