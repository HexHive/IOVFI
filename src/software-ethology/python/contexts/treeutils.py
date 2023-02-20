import os
import pickle
import statistics

import contexts.FBDecisionTree as FBDtree
from sklearn.metrics import f1_score


class TreeEvaluation:
    def __init__(self, tree_path):
        self.tree_path = os.path.abspath(tree_path)
        self.f_scores = dict()

    def add_evaluation(self, guess_path, dtree=None, verbose=False,
                       equivalence_map=None, singletons_only=False):
        with open(guess_path, 'rb') as f:
            guesses = pickle.load(f)

        if dtree is None:
            with open(self.tree_path, 'rb') as f:
                dtree = pickle.load(f)

        f_score = get_evaluation(dtree, guesses, equivalence_map=equivalence_map,
                                 singletons_only=singletons_only)
        if verbose:
            print("Latest F Score: {}".format(f_score))

        self.f_scores[guess_path] = f_score
        if verbose:
            print("Average F Score: {}".format(statistics.mean(self.f_scores)))

    def __str__(self):
        result = "F Scores for {}\n".format(self.tree_path)
        for guess_path, f_score in self.f_scores.items():
            result += "\t{}: {}\n".format(guess_path, f_score)
        if len(self.f_scores):
            result += "Average = {}\n".format(
                statistics.mean(self.f_scores.values()))

        return result


def get_preds_and_truths(tree, guesses, equivalence_map=None, singletons_only=False):
    tree_funcs = list()
    for fd in tree.get_func_descs():
        tree_funcs.append(fd.name)

    preds = list()
    truths = list()
    unknown = "@@UNKNOWN@@"

    for fd, equiv_class in guesses.items():
        fd_name = fd.name
        if singletons_only and equiv_class is not None and len(equiv_class) > 1:
            continue
        if equivalence_map is not None and fd_name in equivalence_map:
            fd_name = equivalence_map[fd_name]

        if equiv_class is None:
            preds.append(unknown)
        else:
            found = False
            for ec in equiv_class:
                ec_name = ec.name
                if equivalence_map is not None and ec_name in equivalence_map:
                    ec_name = equivalence_map[ec_name]

                if fd_name == ec_name:
                    preds.append(ec_name)
                    found = True
                    break
            if not found:
                preds.append(ec_name)

        if fd_name in tree_funcs:
            truths.append(fd_name)
        else:
            truths.append(unknown)

    return preds, truths


def get_evaluation(tree, guesses, equivalence_map=None, singletons_only=False):
    preds, truths = get_preds_and_truths(tree=tree, guesses=guesses,
                                         equivalence_map=equivalence_map)
    return f1_score(truths, preds, average='micro')


def classify_guesses(tree, guesses, equivalence_map=None):
    func_names = set()
    true_pos = set()
    true_neg = set()
    labeled_known_when_unknown = set()
    labeled_unknown_when_known = set()
    labeled_incorrectly = set()

    for fd in tree.get_func_descs():
        func_names.add(fd.name)

    for func_desc, guess in guesses.items():
        if "ifunc" in func_desc.name:
            continue

        if guess is not None:
            found = False
            for ec in guess:
                if "ifunc" in ec.name:
                    continue

                ec_name = ec.name
                func_desc_name = func_desc.name

                if equivalence_map is not None:
                    if ec_name in equivalence_map:
                        ec_name = equivalence_map[ec_name]
                    if func_desc_name in equivalence_map:
                        func_desc_name = equivalence_map[func_desc_name]

                if ec_name == func_desc_name:
                    found = True
                    break

            if found:
                true_pos.add(func_desc.name)
            else:
                path = get_tree_path(tree, func_desc.name)
                if len(path) > 0:
                    labeled_incorrectly.add(func_desc.name)
                else:
                    labeled_known_when_unknown.add(func_desc.name)
        else:
            if func_desc.name in func_names:
                labeled_unknown_when_known.add(func_desc.name)
            else:
                true_neg.add(func_desc.name)

    true_pos_list = list(true_pos)
    true_pos_list.sort()

    true_neg_list = list(true_neg)
    true_neg_list.sort()

    labeled_incorrectly_list = list(labeled_incorrectly)
    labeled_incorrectly_list.sort()

    labeled_known_when_unknown_list = list(labeled_known_when_unknown)
    labeled_known_when_unknown_list.sort()

    labeled_unknown_when_known_list = list(labeled_unknown_when_known)
    labeled_unknown_when_known_list.sort()

    return true_pos_list, true_neg_list, labeled_incorrectly_list, labeled_known_when_unknown_list, labeled_unknown_when_known_list


def get_tree_coverage(dtree, target_func_desc_name):
    tree_path = get_tree_path(dtree, target_func_desc_name)
    path_coverages = list()
    for node in tree_path:
        if isinstance(node, FBDtree.FBDecisionTreeInteriorNode):
            for (func_desc, coverage) in node.get_coverage().items():
                if func_desc.name == target_func_desc_name:
                    path_coverages.append(coverage)
    return path_coverages


def get_individual_tree_coverage(dtree):
    coverages = dict()
    for func_desc in dtree.get_func_descs():
        coverages[func_desc] = get_tree_coverage(dtree, func_desc.name)
    return coverages


def get_full_tree_coverage(dtree):
    executed_instructions = set()
    reachable_instructions = set()
    instruction_mapping = dict()
    for func_desc in dtree.get_func_descs():
        for addr in func_desc.instructions:
            instruction_mapping[addr] = func_desc

    for node in dtree.get_all_interior_nodes():
        for func_desc, coverage_data in node.get_coverage().items():
            for addr in coverage_data:
                curr_func = instruction_mapping[addr]
                executed_instructions.add(addr)
                for inst in curr_func.instructions:
                    reachable_instructions.add(inst)

    return len(executed_instructions) / len(reachable_instructions)


def get_tree_path(tree, func_name):
    path = list()
    path.append(tree.root)
    if _dfs_tree(func_name, path):
        return path
    path.pop()
    return path


def _dfs_tree(func_name, path):
    if path[-1].is_leaf():
        for ec in path[-1].get_equivalence_class():
            if ec.name == func_name:
                return True
        return False
    else:
        path.append(path[-1].get_left_child())
        if _dfs_tree(func_name, path):
            return True
        path.pop()
        path.append(path[-1].get_right_child())
        if _dfs_tree(func_name, path):
            return True
        path.pop()
        return False


def bin_ec_sizes(tree, max_ec_size=10):
    equiv_classes = tree.get_all_equiv_classes()
    bins = dict()
    for idx in range(1, max_ec_size + 1):
        bins[idx] = 0

    for ec in equiv_classes:
        ec_size = len(ec)
        if ec_size >= max_ec_size:
            bins[max_ec_size] += 1
        else:
            bins[ec_size] += 1

    return bins
