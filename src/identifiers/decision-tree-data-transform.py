#!/usr/bin/python3

import argparse
from sklearn import tree
from sklearn.feature_extraction import DictVectorizer
import pandas as pd
from collections import defaultdict
import sys


def parser(value):
    if value is None:
        return None

    try:
        ret = float(value)
        return ret
    except:

    try:
        ret = int(value)
        return ret
    except:

    return str(value)


def load_file(fname):
    print("parsing CSV...", end="")
    sys.stdout.flush()
    data = pd.read_csv(fname, error_bad_lines=False, warn_bad_lines=True)
    print("done!")

    examples = list()
    label = list()

    for line in data.values:
        values = [float(x) for x in line[1:] if x != "?"]
        examples.append(values)
        label.append(line[0])

    fvdicts = defaultdict(dict)

    for idx in range(len(label)):
        fvdicts[label[idx]][idx] = 1

    dual_labels = list()
    dual_features = list()

    for key in fvdicts:
        dual_labels.append(key)
        dual_features.append(fvdicts[key])

    dv = DictVectorizer()
    X = dv.fit_transform(dual_features)

    dtree = tree.DecisionTreeClassifier()
    dtree.fit(X, dual_labels)

    tree.export_graphviz(dtree, out_file="dtree.dot")

    print(dv.get_feature_names())


if __name__ == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument("dataf", type=str, help="TODO")

    args = argp.parse_args()

    load_file(args.dataf)
