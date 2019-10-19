#!/usr/bin/python3

import pickle
import argparse


def main():
    parser = argparse.ArgumentParser(description="Compares two code bases")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin", required=True)
    parser.add_argument("-g", dest="guesses", default="guesses.bin", help="/path/to/guesses.bin", required=True)

    args = parser.parse_args()
    with open(args.tree, 'rb') as f:
        tree = pickle.load(f)

    with open(args.guesses, 'rb') as f:
        guesses = pickle.load(f)

    tree_funcs = list()
    for equiv_class in tree.get_all_equiv_classes():
        for func_desc in equiv_class:
            tree_funcs.append(func_desc.name)

    guess_map = dict()
    for func_desc, guess in guesses.items():
        guess_map[func_desc.name] = guess

    changed_funcs = list()
    same_funcs = list()
    for name in tree_funcs:
        if name not in guess_map:
            changed_funcs.append(name)
            continue

        equiv_class = tree.get_equiv_classes(guess_map[name])
        if equiv_class is None:
            changed_funcs.append(name)
            continue

        found = False
        for ec in equiv_class:
            if ec.name == name:
                same_funcs.append(name)
                found = True
                break

        if not found:
            changed_funcs.append(name)

    print("Same ({}): {}".format(len(same_funcs), " ".join(same_funcs)))
    print("Diff ({}): {}".format(len(changed_funcs), " ".join(changed_funcs)))


if __name__ == "__main__":
    main()
