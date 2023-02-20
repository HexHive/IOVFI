#!/usr/bin/python3

import argparse
import os
import pickle

import contexts.treeutils as tu

equivalences = {
    '__strncmp_sse2': '__strncmp',
    '__strncmp_sse42': '__strncmp',
    '__strncmp_ssse3': '__strncmp',
    '__strncmp_avx2': '__strncmp',
    '_pcre2_strncmp_8': '__strncmp',
    '_pcre2_strncmp_c8_8': '__strncmp',
    '__strncasecmp_sse2': '__strncmp',
    '__memcmp_avx2_movbe': '__memcmp',
    '__memcmp_sse2': '__memcmp',
    '__memcmp_sse4_1': '__memcmp',
    '__memcmp_ssse3': '__memcmp',
    '__wmemcmp_sse4_1': '__memcmp',
    '__wmemcmp_ssse3': '__memcmp',
    '__wmemcmp_sse2': '__memcmp',
    '__wmemcmp_avx2_movbe': '__memcmp',
    '__strnlen_avx2': '__strnlen',
    '__strnlen_sse2': '__strnlen',
    '__strlen_avx2': '__strlen',
    '__strlen_sse2': '__strlen',
    '__mempcpy_sse2_unaligned': '__mempcpy',
    '__mempcpy_avx512_no_vzeroupper': '__mempcpy',
    '__mempcpy_avx512_unaligned': '__mempcpy',
    '__mempcpy_avx_unaligned_erms': '__mempcpy',
    '__mempcpy_erms': '__mempcpy',
    '__mempcpy_sse2_unaligned_erms': '__mempcpy',
    '__mempcpy_ssse3': '__mempcpy',
    '__mempcpy_ssse3_back': '__mempcpy',
    '__mempcpy_avx_unaligned': '__mempcpy',
    '__strncasecmp_avx': '__strcmp',
    '__strncasecmp_ssse3': '__strcmp',
    '__strncasecmp_l_nonascii': '__strcmp',
    '__strcmp_avx2': '__strcmp',
    '__strcmp_ssse3': '__strcmp',
    '__strcmp_sse2_unaligned': '__strcmp',
    '__strcmp_sse2': '__strcmp',
    'c_strcasecmp': '__strcmp',
    '__memset_erms': '__memset',
    '__memset_avx2_unaligned': '__memset',
    '__memset_avx2_unaligned_erms': '__memset',
    '__memset_avx512_erms': '__memset',
    '__memset_avx512_no_vzeroupper': '__memset',
    '__memset_sse2_unaligned': '__memset',
    '__memset_sse2_unaligned_erms': '__memset',
    '__memset_avx2_erms': '__memset',
    '__wcsnlen_sse4_1': '__wcsnlen',
    '__wcsnlen_avx2': '__wcsnlen',
    '__wcsnlen_sse2': '__wcsnlen',
    '__memcpy_ssse3_back': '__memcpy',
    '__memcpy_ssse3': '__memcpy',
    '__strncpy_avx2': '__memcpy',
    '__strncpy_ssse3': '__memcpy',
    '__strncpy_sse2_unaligned': '__memcpy',
    '__mempcpy_chk_erms': '__mempcpy_chk',
    '__mempcpy_chk_avx512_no_vzeroupper': '__mempcpy_chk',
    '__mempcpy_chk_ssse3': '__mempcpy_chk',
    '__mempcpy_chk_ssse3_back': '__mempcpy_chk',
    '__wmempcpy': '__wmemcpy',
    'wmemmove': '__wmemcpy',
    '__memmove_avx_unaligned': '__memmove',
    '__memmove_avx_unaligned_erms': '__memmove',
    '__memmove_ssse3': '__memmove',
    '__memmove_ssse3_back': '__memmove',
    '__memchr_sse2': '__memchr',
    '__memchr_avx2': '__memchr',
    '__wmemchr_sse2': '__memchr',
    '_IO_wpadn': '_IO_padn',
    'iswalnum': 'c_isalnum',
    '__wmemchr_avx2': '__memchr_avx2',
    '__iswprint': 'c_isprint',
    '__strcpy_avx2': "__strcpy",
    '__strcpy_ssse3': '__strcpy',
    '__strcpy_sse2': '__strcpy',
    '__strcpy_sse2_unaligned': '__strcpy',
    '__strcat_avx2': '__strcat',
    '__strcat_sse2': '__strcat',
    '__strcat_sse2_unaligned': '__strcat',
    '__strcat_ssse3': '__strcat',
    '__stpncpy_ssse3': '__stpncpy',
    '__stpncpy_sse2_unaligned': '__stpncpy',
    '__stpncpy_sse2': '__stpncpy',
    '__stpncpy_avx2': '__stpncpy',
    '__stpcpy_avx2': '__stpcpy',
    '__stpcpy_ssse3': '__stpcpy',
    '__IO_vsprintf': '__vsprintf',
    '__vsnprintf_internal': '__vsnprintf',
    '__vfprintf_internal': '__vfprintf',
    'vfprintf': '__vfprintf',
    '__gnu_dev_major': 'gnu_dev_major',
    '__gnu_dev_minor': 'gnu_dev_minor',
    'get_common_indices.constprop.0': 'get_common_indices.constprop',
    'get_common_indeces.constprop.1': 'get_common_indeces.constprop',
    '__malloc_info.part.0': '__malloc_info.part',
    '__malloc_info.part.10': '__malloc_info.part',
    '__isoc99_sscanf': '__sscanf',
    '_IO_sscanf': '__sscanf',
    '_IO_str_pbackfail': '_IO_default_pbackfail',
}


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/list",
                        default="guesses.txt")
    parser.add_argument("-output", "-o", help="/path/to/measurement.bin")
    parser.add_argument('-verbose', help="Print out additional information",
                        type=str2bool, nargs='?', const=True,
                        default=False)
    parser.add_argument('-s', dest='singletons_only', help='Only compute accuracy for '
                                   'equivalence classes of size 1 or Unknown',
                                    action='store_true')
    parser.add_argument('-tree_label', type=str, help='DTree label')
    parser.add_argument('-compilation_level', type=str, help='Compilation environment '
                                                             'of test program')

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    if args.output is not None and os.path.exists(args.output):
        with open(args.output, 'rb') as f:
            evaluation = pickle.load(f)
    else:
        evaluation = tu.TreeEvaluation(args.tree)

    with open(args.guesses, "r") as guessList:
        for guessLine in guessList.readlines():
            guessLine = guessLine.strip()

            print("Computing accuracy for {}\n".format(guessLine))
            with open(guessLine, "rb") as guessFile:
                guesses = pickle.load(guessFile)

            if args.verbose:
                true_pos, true_neg, incorrect_labels, known_when_unknown, unknown_when_known = \
                    tu.classify_guesses(dtree, guesses, equivalences)
                sorted_names = list()
                for name in true_pos:
                    sorted_names.append(name)

                sorted_names.sort()
                print("--------------------- True Pos -------------------")
                print(sorted_names)
                print()
                sorted_names.clear()

                for name in incorrect_labels:
                    sorted_names.append(name)
                sorted_names.sort()
                print("------------------ incorrect_labels ----------------")
                print(sorted_names)
                print()
                sorted_names.clear()

                for name in known_when_unknown:
                    sorted_names.append(name)
                sorted_names.sort()
                print("----------------- known_when_unknown ---------------")
                print(sorted_names)
                print()
                sorted_names.clear()

                for name in unknown_when_known:
                    sorted_names.append(name)
                sorted_names.sort()
                print("----------------- unknown_when_known ---------------")
                print(sorted_names)
                print()
                sorted_names.clear()

            evaluation.add_evaluation(guess_path=guessLine, dtree=dtree,
                                      verbose=args.verbose,
                                      singletons_only=args.singletons_only,
                                      tree_label=args.tree_label,
                                      compilation_label=args.compilation_label)

    print(evaluation)
    if args.output is not None:
        with open(args.output, 'wb') as outfile:
            pickle.dump(evaluation, outfile)


if __name__ == "__main__":
    main()
