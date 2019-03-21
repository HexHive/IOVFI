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
