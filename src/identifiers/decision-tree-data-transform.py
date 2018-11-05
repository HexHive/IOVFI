#!/usr/bin/python3

import argparse
from sklearn import tree
from sklearn.feature_extraction import DictVectorizer
import pandas as pd
from collections import defaultdict
import sys
import numpy as np
import decimal

pointer_count = 0
identifier_node_names = {}


def parser(value):
    if value is None or value == '?':
        return None

    return str(value)


def find_type_name(val):
    try:
        int(val)
        return "int"
    except ValueError:
        # print("{} is not an int".format(val))
        pass

    try:
        decimal.Decimal(val)
        return "double"
    except decimal.InvalidOperation:
        # print("{} is not a double".format(val))
        pass

    try:
        np.longdouble(val)
        return "long double"
    except:
        pass

    return "char*"


def output_leaf(function_name, node_id):
    name = "{}_".format(function_name)
    identifier_node_names[node_id] = name
    leaf_str = "std::shared_ptr<fbf::FunctionIdentifierNode> {} = std::make_shared<fbf::FunctionIdentifierNode>(\"{" \
               "}\");".format(name,
                              function_name)
    return leaf_str


def output_identifier(io_vec, node_id):
    template_sig = []
    args = []

    prestring = ""
    pointer_count = 0

    idx = 0
    while idx < len(io_vec) and io_vec[idx] is not None:
        if idx == 1:
            # Skip over argument count
            idx += 1
            continue

        type_name = find_type_name(io_vec[idx])
        template_sig.append(type_name)

        if type_name.find("*") >= 0:
            buffer_name = "buf_" + str(pointer_count)
            # 4 comes from the fact that hex digits are written as \xFF or 4 characters per one value
            buffer_len = int(len(io_vec[idx]) / 4)
            prestring += "{} {} = ({}) malloc({});\n".format(type_name, buffer_name, type_name, buffer_len + 1)
            prestring += "if({}) {{ buffers_.push_back({}); std::memcpy({}, \"{}\", {}); }} else {{ throw " \
                         "std::runtime_error(\"malloc failed\"); " \
                         "}}\n".format(buffer_name, buffer_name, buffer_name, io_vec[idx], buffer_len)
            pointer_count += 1
            args.append(buffer_name)
        else:
            args.append(io_vec[idx])

        idx += 1

    if len(template_sig) == 1:
        template_sig.append("void")

    name = "node" + str(node_id)
    identifier_node_names[node_id] = name
    template_str = ", ".join(template_sig)
    arg_str = ", ".join(args)

    obj_str = "{}std::shared_ptr<fbf::FunctionIdentifierInternalNode<{}>> {} = " \
              "std::make_shared<fbf::FunctionIdentifierInternalNode<{" \
              "}>>({});".format(
        prestring, template_str, name, template_str, arg_str)

    return obj_str


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

    examples = data.values[:, 1:]
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

    dtree = tree.DecisionTreeClassifier()
    dtree.fit(X, dual_labels)

    tree.export_graphviz(dtree, out_file="dtree.dot")

    classifier_tree = dtree.tree_
    node_count = classifier_tree.node_count
    node_depth = np.zeros(shape=node_count, dtype=np.int64)
    is_leaves = np.zeros(shape=node_count, dtype=bool)

    children_left = classifier_tree.children_left
    children_right = classifier_tree.children_right
    feature = classifier_tree.feature
    working_stack = [(0, -1)]

    parents = {}

    while len(working_stack) > 0:
        node_id, parent_depth = working_stack.pop()
        node_depth[node_id] = parent_depth + 1

        if children_left[node_id] != children_right[node_id]:
            working_stack.append((children_left[node_id], parent_depth + 1))
            working_stack.append((children_right[node_id], parent_depth + 1))
            parents[children_left[node_id]] = node_id
            parents[children_right[node_id]] = node_id
        else:
            is_leaves[node_id] = True

    for i in range(node_count):
        io_vec = dv.get_feature_names()[feature[i]]
        idx = 0
        if is_leaves[i]:
            for leaf in dtree.apply(X):
                if leaf == i:
                    break
                idx += 1
            function_name = dual_labels[idx]
            leaf_str = output_leaf(function_name, i)
            print(leaf_str)
        else:
            obj_str = output_identifier(io_vec, i)
            print(obj_str)

    for child in children_right:
        if child in parents:
            p = identifier_node_names[parents[child]]
            c = identifier_node_names[child]
            parent_str = "{}->set_pass_node({});".format(p, c)
            print(parent_str)

    for child in children_left:
        if child in parents:
            p = identifier_node_names[parents[child]]
            c = identifier_node_names[child]
            parent_str = "{}->set_fail_node({});".format(p, c)
            print(parent_str)

    # for i in range(node_count):
    #     io_vec = dv.get_feature_names()[feature[i]]
    #     if is_leaves[i]:
    #         idx = 0
    #         for leaf in dtree.apply(X):
    #             if leaf == i:
    #                 break
    #             idx += 1
    #         function_name = dual_labels[idx]
    #         print("%snode=%d leaf node (%s)." % (node_depth[i] * "\t", i, function_name))
    #     else:
    #         function_test = "func("
    #         idx = 2
    #         count = 0
    #         while idx < len(io_vec) and io_vec[idx] is not None:
    #             function_test += str(io_vec[idx])
    #             function_test += ","
    #             idx += 1
    #             count += 1
    #         if count > 0:
    #             function_test = function_test[:-1]
    #         function_test += ") == "
    #         function_test += str(io_vec[0])
    #
    #         print("%snode=%s test node: go to node %s if %s else to "
    #               "node %s."
    #               % (node_depth[i] * "\t",
    #                  i,
    #                  children_right[i],
    #                  function_test,
    #                  children_left[i],
    #                  ))
    # print()


if __name__ == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument("dataf", type=str, help="TODO")

    args = argp.parse_args()

    load_file(args.dataf)
