#!/usr/bin/python3

import argparse
from sklearn import tree
from sklearn.feature_extraction import DictVectorizer
import pandas as pd
from collections import defaultdict
import sys
import numpy as np
import decimal
import pygraphviz as pgv
import random

pointer_count = 0
identifier_node_names = {}
dtree_graph = pgv.AGraph()

class CSVArg(object):
    def __init__(self, val):
        temp_val = str(val)
        try:
            if temp_val[-1] == 'l':
                self.value = decimal.Decimal(temp_val[:-1])
                self.type_str = "long double"
                return
        except decimal.InvalidOperation:
            pass

        try:
            if temp_val[-1] == 'f':
                self.value = decimal.Decimal(temp_val[:-1])
                self.type_str = "float"
                return
        except decimal.InvalidOperation:
            pass

        try:
            self.value = int(temp_val)
            self.type_str = "int"
        except ValueError:
            pass

        try:
            self.value = decimal.Decimal(temp_val)
            self.type_str = "double"
        except decimal.InvalidOperation:
            pass

        self.value = temp_val
        if temp_val == "(nil)":
            self.type_str = "void"
        else:
            self.type_str = "char*"
    def __cmp__(self, other):
        if self.type_str == "char*":
            if other.type_str == "char*":
                if self.value < other.value:
                    return -1
                elif self.value == other.value:
                    return 0
                else:
                    return 1
            else:
                return 1
        else:
            if other.type_str == "char*":
                return -1
            else:
                if self.value < other.value:
                    return -1
                elif self.value == other.value:
                    return 0
                else:
                    return 1
    def __lt__(self, other):
        return self.__cmp__(other) < 0
    def __eq__(self, other):
        return self.__cmp__(other) == 0
    def __hash__(self):
        return hash(self.value)
    def __str__(self):
        return str(self.value)

def parser(value):
    if value is None or value == '?':
        return None

    return CSVArg(value)


def find_type_name(val):
    return val.type_str
    # print("{}: {}".format(type(val), val))
    # if val.value == "(nil)":
    #     return "void"
    #
    # try:
    #     if 'l' in val:
    #         decimal.Decimal(str(val)[:-1])
    #         return "long double"
    # except decimal.InvalidOperation:
    #     pass
    #
    # try:
    #     if 'f' in val:
    #         decimal.Decimal(str(val)[:-1])
    #         return "float"
    # except decimal.InvalidOperation:
    #     pass
    #
    # try:
    #     int(val)
    #     return "int"
    # except ValueError:
    #     pass
    #
    # try:
    #     decimal.Decimal(val)
    #     return "double"
    # except decimal.InvalidOperation:
    #     pass
    #
    # return "char*"


def output_leaf(function_name, node_id, node_count, feature_dict):
    if node_id == 0:
        name = "root_"
    else:
        name = "{}_".format(function_name)

    confirmation_id = node_id + node_count
    identifier_node_names[node_id] = name
    io_vec_set = list(feature_dict[function_name].keys())
    io_vec = io_vec_set[random.randint(0, len(io_vec_set) - 1)]
    leaf_str = output_identifier(io_vec, confirmation_id, True)
    leaf_str += "\nstd::shared_ptr<fbf::FunctionIdentifierNode> {} = std::make_shared<fbf::FunctionIdentifierNode>(" \
                "\"{" \
               "}\", {});".format(name,
                              function_name, identifier_node_names[confirmation_id])
    dtree_graph.add_node(node_id)
    dtree_graph.get_node(node_id).attr['label'] = function_name
    return leaf_str


def output_identifier(io_vec, node_id, is_confirmation = False):
    template_sig = []
    args = []
    sizes = []
    label = []

    prestring = ""
    arg_count = 0
    postcall = []

    global pointer_count
    idx = 0
    while idx < len(io_vec):
        if io_vec[idx] is None:
            idx += 1
            continue

        if idx == 1:
            arg_count = int(io_vec[idx])
            idx += 1
            continue

        type_name = find_type_name(io_vec[idx])
        # The first two arguments are return value and arity
        if idx - 2 <= arg_count:
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
            if idx - 2 >= arg_count:
                postcall.append(buffer_name)
            else:
                args.append(buffer_name)
                sizes.append(str(buffer_len))
                label.append(buffer_name)
        else:
            if type_name is not "void":
                if idx - 2 >= arg_count:
                    postcall.append(io_vec[idx])
                else:
                    args.append(io_vec[idx])
                    label.append(io_vec[idx])
                    sizes.append("sizeof({})".format(type_name))
            else:
                label.append("void")

        idx += 1

    if node_id == 0:
        name = "root"
    else:
        name = "node" + str(node_id)

    identifier_node_names[node_id] = name
    template_str = ", ".join(template_sig)
    if label[0] != "void":
        arg_str = "{}, {}, std::vector<size_t>({{{}}}), std::make_tuple({}), std::make_tuple({})".format(args[0],
                                                                                                       sizes[0],
                                                                                                 ",".join(sizes[1:]),
                                                                                                 ",".join(args[1:]),
                                                                                                 ",".join(postcall))
    else:
        arg_str = "std::vector<size_t>({{{}}}), std::make_tuple({}), std::make_tuple({})".format(",".join(sizes),
                                                                                         ",".join(args),
                                                                                         ",".join(postcall))

    if not is_confirmation:
        dtree_graph.add_node(node_id)
        dtree_graph.get_node(node_id).attr['label'] = ",".join(label)

    obj_str = "{}std::shared_ptr<fbf::FunctionIdentifierInternalNode<{}>> {} = " \
              "std::make_shared<fbf::FunctionIdentifierInternalNode<{" \
              "}>>({});".format(
        prestring, template_str, name, template_str, arg_str)

    return obj_str


def load_file(fname):
    print("parsing CSV...", end="", file=sys.stderr)
    sys.stderr.flush()
    data = pd.read_csv(fname, error_bad_lines=False, warn_bad_lines=True,
                       converters={"return": parser, "arg0": parser, "arg1": parser,
                                   "arg2": parser, "arg3": parser, "arg4": parser,
                                   "arg5": parser, "arg6": parser, "arg7": parser,
                                   "arg8": parser, "arg9": parser, "arg10": parser,
                                   "arg11": parser, "post0": parser, "post1": parser,
                                   "post2": parser, "post3": parser, "post4": parser,
                                   "post5": parser, "post6": parser, "post7": parser,
                                   "post8": parser, "post9": parser, "post10": parser,
                                   "post11": parser})
    print("done!", file=sys.stderr)

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
        if is_leaves[i]:
            idx = 0
            for leaf in dtree.apply(X):
                if leaf == i:
                    break
                idx += 1
            function_name = dual_labels[idx]
            leaf_str = output_leaf(function_name, i, node_count, fvdicts)
            print(leaf_str)
        else:
            io_vec = dv.get_feature_names()[feature[i]]
            print(io_vec)
            obj_str = output_identifier(io_vec, i)
            print(obj_str)

    for child in children_right:
        if child in parents:
            p = identifier_node_names[parents[child]]
            c = identifier_node_names[child]
            dtree_graph.add_edge(parents[child], child)
            parent_str = "{}->set_pass_node({});".format(p, c)
            print(parent_str)

    for child in children_left:
        if child in parents:
            p = identifier_node_names[parents[child]]
            c = identifier_node_names[child]
            dtree_graph.add_edge(parents[child], child)
            parent_str = "{}->set_fail_node({});".format(p, c)
            print(parent_str)

    dtree_graph.write('dtree_labeled.dot')


if __name__ == "__main__":
    argp = argparse.ArgumentParser()
    argp.add_argument("dataf", type=str, help="TODO")

    args = argp.parse_args()

    random.seed()
    load_file(args.dataf)
