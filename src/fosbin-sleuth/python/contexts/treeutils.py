def diff_two_guess_sets(guesses0, guesses1):
    funcs0 = dict()
    funcs1 = dict()
    for fd, idx in guesses0.items():
        funcs0[fd.name] = idx
    for fd, idx in guesses1.items():
        funcs1[fd.name] = idx

    missing_in_0 = set()
    missing_in_1 = set()
    differing = set()
    for name, idx in funcs0.items():
        if name not in funcs1:
            missing_in_1.add(name)
        elif idx != funcs1[name]:
            differing.add(name)

    for name, idx in funcs1.items():
        if name not in funcs0:
            missing_in_0.add(name)
        elif idx != funcs0[name]:
            differing.add(name)

    return missing_in_0, missing_in_1, differing


def get_incorrect(tree, guesses):
    incorrect = set()
    func_names = set()
    for fd in tree.get_func_descs():
        func_names.add(fd.name)

    for fd, idx in guesses.items():
        equiv_class = tree.get_equiv_classes(idx)

        if equiv_class is not None:
            found = False
            for ec in equiv_class:
                if ec.name == fd.name:
                    found = True
                    break
            if not found:
                incorrect.add(fd.name)
        else:
            if fd.name in func_names:
                incorrect.add(fd.name)

    return incorrect


def get_func_indices(tree):
    tree_funcs = dict()
    for idx in range(0, tree.size()):
        if tree._is_leaf(idx):
            for ec in tree.get_equiv_classes(idx):
                tree_funcs[ec.name] = idx

    return tree_funcs

def output_incorrect(tree, guesses):
    incorrect = get_incorrect(tree, guesses)
    tree_funcs = dict()
    for idx in range(0, tree.size()):
        if tree._is_leaf(idx):
            equiv_classes = tree.get_equiv_classes(idx)
            for ec in equiv_classes:
                tree_funcs[ec.name] = idx

    for fd, guess in guesses.items():
        if fd.name in incorrect:
            correct = list()
            if fd.name in tree_funcs:
                equiv_classes = tree.get_equiv_classes(tree_funcs[fd.name])
                for ec in equiv_classes:
                    correct.append(ec.name)
                correct.sort()
            else:
                correct.append("UNKNOWN")

            equiv_classes = tree.get_equiv_classes(guess)
            if equiv_classes is not None:
                names = list()
                for ec in equiv_classes:
                    names.append(ec.name)
                names.sort()
                print("{}: {} <--> {}".format(fd.name, " ".join(names), " ".join(correct)))
            else:
                print("{}: UNKNOWN <--> {}".format(fd.name, " ".join(correct)))
            print()
