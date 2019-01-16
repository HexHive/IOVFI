#!/usr/bin/python3

import os
import sys
import argparse
import pickle
from sklearn import tree, preprocessing
import numpy
from sklearn.externals.six import StringIO
from contexts import FBDecisionTree


def main():
    parser = argparse.ArgumentParser(description="GenDecisionTree")
    parser.add_argument('-m', '--map', help="Output of which contexts execute with which functions", default="out.desc")
    parser.add_argument('-t', '--tree', help="File to output decision tree", default="tree.bin")

    results = parser.parse_args()
    treeFile = open(results.tree, "wb+")
    descFile = open(results.map, "rb")
    dotFile = open(os.path.basename(results.tree) + ".dot", "w+")

    print("Loading map...", end='')
    sys.stdout.flush()
    descMap = pickle.load(descFile)
    print("done!")
    labels = preprocessing.LabelEncoder()

    hash_labels = set()
    print("Transforming function labels...", end='')
    sys.stdout.flush()
    for hashes in descMap.keys():
        hash_labels.add(hashes)
    labels.fit_transform(list(hash_labels))
    print("done!")

    funcs_labels = list()
    funcs_features = list()

    print("Reading in function labels...", end='')
    sys.stdout.flush()
    for key, funcs in descMap.items():
        idx = labels.transform([key])[0]
        for func in funcs:
            if func not in funcs_labels:
                funcs_labels.append(func)
                funcs_features.append(numpy.zeros(len(labels.classes_), dtype=bool))
            func_feature = funcs_features[funcs_labels.index(func)]
            func_feature[idx] = True
    print("done!")

    print("Total Function Count: {}".format(len(funcs_labels)))

    dtree = tree.DecisionTreeClassifier()
    print("Creating decision tree...", end='')
    sys.stdout.flush()
    dtree.fit(funcs_features, funcs_labels)
    fbDtree = FBDecisionTree.FBDecisionTree(dtree, labels)
    pickle.dump(fbDtree, treeFile)
    print("done!")

    print("Generating dot file...", end='')
    sys.stdout.flush()
    dot_data = StringIO()
    tree.export_graphviz(dtree, out_file=dot_data, filled=True, rounded=True, special_characters=True)
    dotFile.write(dot_data.getvalue())
    print("done!")

    # conflicts = set()
    # totalConflicts = 0
    # for idx in range(dtree.tree_.node_count):
    #     if dtree.tree_.children_left[idx] == dtree.tree_.children_right[idx]:
    #         if dtree.tree_.n_node_samples[idx] > 1:
    #             print("Conflicts: ", end='')
    #             totalConflicts += 1
    #             for idx2 in range(len(dtree.tree_.value[idx][0])):
    #                 if dtree.tree_.value[idx][0][idx2]:
    #                     conflicts.add(dtree.classes_[idx2])
    #                     print(dtree.classes_[idx2], end=' ')
    #             print()
    #             a1 = None
    #             a1Idx = None
    #             for idx2 in range(len(dtree.tree_.value[idx][0])):
    #                 if dtree.tree_.value[idx][0][idx2]:
    #                     if a1 is None:
    #                         a1 = funcs_features[funcs_labels.index(dtree.classes_[idx2])]
    #                         a1Idx = idx2
    #                     else:
    #                         a2 = funcs_features[funcs_labels.index(dtree.classes_[idx2])]
    #
    #             print("\n")
    #         else:
    #             print("Unique: {}".format(dtree.classes_[idx]))

if __name__ == "__main__":
    main()
