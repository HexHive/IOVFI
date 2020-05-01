import contexts.FBDecisionTree as FBDtree


def get_evaluation(tree, guesses, equivalence_map=None):
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
            
        if func_desc.name == 'version_etc_arn':
            print("evaluating version_etc_arn")

        if guess is not None:
            found = False
            for ec in guess:
                if func_desc.name == 'version_etc_arn':
                    print("guess: {}".format(ec.name))
                if "ifunc" in ec.name:
                    continue

                ec_name = ec.name
                func_desc_name = func_desc.name

                if equivalence_map is not None:
                    if ec_name in equivalence_map:
                        ec_name = equivalence_map[ec_name]
                    if func_desc_name in equivalence_map:
                        func_desc_name = equivalence_map[func_desc_name]

                if func_desc.name == 'version_etc_arn':
                    print("{} vs {}".format(func_desc_name, ec.name))
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

# def compute_path_coverage(dtree, func_name):
#     path = get_tree_path(dtree, func_name)
#     executed_instructions = list()
#     total_instruction_count = list()
#     for node in path:
#         if isinstance(node, FBDtree.FBDecisionTreeInteriorNode):
#             for (func_desc, coverage) in node.get_coverage().items():
#                 if func_desc.name == func_name:
#                     for (instructions, total_instructions) in coverage:
#                         executed_instructions.append(len(instructions))
#                         total_instruction_count.append(total_instructions)
#                     break
#
#     if sum(total_instruction_count) > 0:
#         return sum(executed_instructions) / sum(total_instruction_count)
#     else:
#         return 0

# def get_func_indices(tree):
#     tree_funcs = dict()
#     for idx in range(0, tree.size()):
#         if tree._is_leaf(idx):
#             for ec in tree.get_equiv_classes(idx):
#                 tree_funcs[ec.name] = idx
#
#     return tree_funcs


# def output_incorrect(tree, guesses):
#     true_pos, true_neg, incorrect = get_evaluation(tree, guesses)
#     tree_funcs = dict()
#     for idx in range(0, tree.size()):
#         if tree._is_leaf(idx):
#             equiv_classes = tree.get_equiv_classes(idx)
#             for ec in equiv_classes:
#                 tree_funcs[ec.name] = idx
#
#     for fd, guess in guesses.items():
#         if fd.name in incorrect:
#             correct = list()
#             if fd.name in tree_funcs:
#                 equiv_classes = tree.get_equiv_classes(tree_funcs[fd.name])
#                 for ec in equiv_classes:
#                     correct.append(ec.name)
#                 correct.sort()
#             else:
#                 correct.append("UNKNOWN")
#
#             equiv_classes = tree.get_equiv_classes(guess)
#             if equiv_classes is not None:
#                 names = list()
#                 for ec in equiv_classes:
#                     names.append(ec.name)
#                 names.sort()
#                 print("{}: {} <--> {}".format(fd.name, " ".join(names), " ".join(correct)))
#             else:
#                 print("{}: UNKNOWN <--> {}".format(fd.name, " ".join(correct)))
#             print()
