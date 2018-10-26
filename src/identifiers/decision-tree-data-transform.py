import argparse
from sklearn import tree
from sklearn.feature_extraction import DictVectorizer
import pandas as pd
from collections import defaultdict


def load_file(fname):
    data = pd.read_csv(fname)

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
