#!/usr/bin/python3

import argparse
from sklearn import tree
from sklearn.feature_extraction import DictVectorizer
import pandas as pd
from collections import defaultdict
import sys
import numpy as np


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

    examples = data.values[:, 1:13]
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

    classifier_tree = dtree.tree_
    node_count = classifier_tree.node_count
    node_depth = np.zeros(shape=node_count, dtype=np.int64)
    is_leaves = np.zeros(shape=node_count, dtype=bool)
    working_stack = [(0, -1)]

    children_left = classifier_tree.children_left
    children_right = classifier_tree.children_right
    feature = classifier_tree.feature

    while len(working_stack) > 0:
        node_id, parent_depth = working_stack.pop()
        node_depth[node_id] = parent_depth + 1

        if children_left[node_id] != children_right[node_id]:
            working_stack.append((children_left[node_id], parent_depth + 1))
            working_stack.append((children_right[node_id], parent_depth + 1))
        else:
            is_leaves[node_id] = True

    print("The binary tree structure has %s nodes and has "
          "the following tree structure:"
          % node_count)
    for i in range(node_count):
        if is_leaves[i]:
            print("%snode=%s leaf node." % (node_depth[i] * "\t", label[feature[i]]))
        else:
            io_vec = examples[feature[i]]
            function_name = label[feature[i]]

            function_test = "func("
            idx = 2
            count = 0
            while io_vec[idx] is not None and idx < len(io_vec):
                function_test += str(io_vec[idx])
                function_test += ","
                idx += 1
                count += 1
            if count > 0:
                function_test = function_test[:-1]
            function_test += ") == "
            function_test += str(io_vec[0])

            print("%snode=%s(%s) test node: go to node %s if %s else to "
                  "node %s."
                  % (node_depth[i] * "\t",
                     i,
                     function_name,
                     children_right[i],
                     function_test,
                     children_left[i],
                     ))
    print()



if __name__ == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument("dataf", type=str, help="TODO")

    args = argp.parse_args()

    load_file(args.dataf)
