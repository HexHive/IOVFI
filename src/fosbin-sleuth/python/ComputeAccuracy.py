#!/usr/bin/python3

import argparse
import pickle
import statistics
import contexts.treeutils as tu

equivalences = {
    '__strncmp_sse2': '__strncmp',
    '__strncmp_sse42': '__strncmp',
    '__strncmp_ssse3': '__strncmp',
    '__memcmp_avx2_movbe': '__memcmp',
    '__memcmp_sse2': '__memcmp',
    '__memcmp_sse4_1': '__memcmp',
    '__memcmp_ssse3': '__memcmp',
    '__strnlen_avx2': '__strnlen',
    '__strnlen_sse2': '__strnlen',
    '__mempcpy_sse2_unaligned': '__mempcpy',
    '__mempcpy_avx512_no_vzeroupper': '__mempcpy',
    '__mempcpy_avx512_unaligned': '__mempcpy',
    '__mempcpy_avx_unaligned_erms': '__mempcpy',
    '__mempcpy_erms': '__mempcpy',
    '__mempcpy_sse2_unaligned_erms': '__mempcpy',
    '__mempcpy_ssse3': '__mempcpy',
    '__mempcpy_ssse3_back': '__mempcpy',
    '__mempcpy_avx_unaligned': '__mempcpy',
    '__strncasecmp_avx': '__strncasecmp',
    '__strncasecmp_ssse3': '__strncasecmp',
    '__strncasecmp_l_nonascii': '__strncasecmp',
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
    '__strnlen_sse2': '__strnlen',
    '__strnlen_avx2': '__strnlen',
    '__memcpy_ssse3_back': '__memcpy',
    '__memcpy_ssse3': '__memcpy',
    '__mempcpy_chk_erms': '__mempcpy_chk',
    '__mempcpy_chk_avx512_no_vzeroupper': '__mempcpy_chk',
    '__mempcpy_chk_ssse3': '__mempcpy_chk',
    '__mempcpy_chk_ssse3_back': '__mempcpy_chk',
    '__memmove_avx_unaligned': '__memmove',
    '__memmove_avx_unaligned_erms': '__memmove',
    '__memmove_ssse3': '__memmove',
    '__memmove_ssse3_back': '__memmove',
    '__memchr_sse2': '__memchr',
    '__memchr_avx2': '__memchr'
}

def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/list", default="guesses.txt")

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    accuracies = list()

    with open(args.guesses, "r") as guessList:
        for guessLine in guessList.readlines():
            guessLine = guessLine.strip()
            print("Computing accuracy for {}".format(guessLine))
            with open(guessLine, "rb") as guessFile:
                guesses = pickle.load(guessFile)

            true_pos, true_neg, incorrect = tu.get_evaluation(dtree, guesses, equivalences)
            accuracy = (len(true_pos) + len(true_neg)) / (len(true_pos) + len(true_neg) + len(incorrect) + len(
                incorrect))
            accuracies.append(accuracy)

    if len(accuracies) > 1:
        avg = statistics.mean(accuracies)
        stddev = statistics.stdev(accuracies)
    elif len(accuracies) == 1:
        avg = accuracies[0]
        stddev = 0
    else:
        raise AssertionError("No guesses provided")

    print("Average Accuracy: {} +- {}".format(avg, stddev))


if __name__ == "__main__":
    main()
