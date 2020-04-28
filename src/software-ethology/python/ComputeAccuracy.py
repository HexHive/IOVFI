#!/usr/bin/python3

import argparse
import os
import pickle
import statistics

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


class TreeEvaluation:
    def __init__(self, tree_path):
        self.tree_path = os.path.abspath(tree_path)
        self.specificities = list()
        self.recalls = list()
        self.accuracies = list()
        self.precisions = list()
        self.guess_paths = list()

    def add_evaluation(self, guess_path, true_pos, true_neg, incorrect, verbose=False):
        self.guess_paths.append(os.path.abspath(guess_path))

        accuracy = (len(true_pos) + len(true_neg)) / (len(true_pos) + len(true_neg) + len(incorrect) + len(
            incorrect))
        self.accuracies.append(accuracy)

        recall = len(true_pos) / (len(true_pos) + len(incorrect))
        self.recalls.append(recall)

        specificity = len(true_neg) / (len(true_neg) + len(incorrect))
        self.specificities.append(specificity)

        precision = len(true_pos) / (len(true_pos) + len(incorrect))
        self.precisions.append(precision)
        if verbose:
            print("Latest accuracy: {}".format(accuracy))
            print("Latest recall: {}".format(recall))
            print("Latest specificity: {}".format(specificity))
            print("Latest precision: {}".format(precision))
            print()

    def __str__(self):
        if len(self.accuracies) > 1:
            avg = statistics.mean(self.accuracies)
            stddev = statistics.stdev(self.accuracies)
            median = statistics.median(self.accuracies)
        elif len(self.accuracies) == 1:
            avg = self.accuracies[0]
            median = self.accuracies[0]
            stddev = 0
        else:
            raise AssertionError("No guesses provided")

        result = "Average Accuracy: {} +- {}\n".format(avg, stddev)
        result += "Median Accuracy: {}\n\n".format(median)

        if len(self.recalls) > 1:
            avg = statistics.mean(self.recalls)
            stddev = statistics.stdev(self.recalls)
            median = statistics.median(self.recalls)
        elif len(self.recalls) == 1:
            avg = self.recalls[0]
            median = self.recalls[0]
            stddev = 0
        else:
            raise AssertionError("No guesses provided")

        result += "Average Recall: {} +- {}\n".format(avg, stddev)
        result += "Median Accuracy: {}\n\n".format(median)

        if len(self.specificities) > 1:
            avg = statistics.mean(self.specificities)
            stddev = statistics.stdev(self.specificities)
            median = statistics.median(self.specificities)
        elif len(self.specificities) == 1:
            avg = self.specificities[0]
            median = self.specificities[0]
            stddev = 0
        else:
            raise AssertionError("No guesses provided")

        result += "Average Specificity: {} +- {}\n".format(avg, stddev)
        result += "Median Specificity: {}\n\n".format(median)

        if len(self.precisions) > 1:
            avg = statistics.mean(self.precisions)
            stddev = statistics.stdev(self.precisions)
            median = statistics.median(self.precisions)
        elif len(self.precisions) == 1:
            avg = self.precisions[0]
            median = self.precisions[0]
            stddev = 0
        else:
            raise AssertionError("No guesses provided")

        result += "Average Precision: {} +- {}\n".format(avg, stddev)
        result += "Median Precision: {}".format(median)

        return result


def main():
    parser = argparse.ArgumentParser(description="Computes Analysis Accuracy")
    parser.add_argument("-tree", default="tree.bin", help="/path/to/tree.bin")
    parser.add_argument("-g", dest="guesses", help="/path/to/guess/list", default="guesses.txt")
    parser.add_argument("-output", "-o", help="/path/to/measurement.bin")

    args = parser.parse_args()

    with open(args.tree, "rb") as treefile:
        dtree = pickle.load(treefile)

    evaluation = TreeEvaluation(args.tree)

    with open(args.guesses, "r") as guessList:
        for guessLine in guessList.readlines():
            guessLine = guessLine.strip()
            print("Computing accuracy for {}\n".format(guessLine))
            with open(guessLine, "rb") as guessFile:
                guesses = pickle.load(guessFile)

            true_pos, true_neg, incorrect_labels, known_when_unknown, unknown_when_known = tu.get_evaluation(dtree,
                                                                                                             guesses,
                                                                                                             equivalences)
            sorted = list()
            for name in true_pos:
                sorted.append(name)

            sorted.sort()
            print("--------------------- True Pos -------------------")
            print(sorted)
            print()
            sorted.clear()

            for name in incorrect:
                sorted.append(name)
            sorted.sort()
            print("--------------------- Incorrect -------------------")
            print(sorted)
            print()
            sorted.clear()

            for name in known_when_unknown:
                sorted.append(name)
            sorted.sort()
            print("----------------- known_when_unknown ---------------")
            print(sorted)
            print()
            sorted.clear()

            for name in unknown_when_known:
                sorted.append(name)
            sorted.sort()
            print("----------------- unknown_when_known ---------------")
            print(sorted)
            print()
            sorted.clear()

            incorrect = list()
            for name in incorrect_labels:
                incorrect.append(name)
            for name in known_when_unknown:
                incorrect.append(name)
            for name in unknown_when_known:
                incorrect.append(name)

            incorrect.sort()
            print(incorrect)

            evaluation.add_evaluation(guessLine, true_pos, true_neg, incorrect, True)

    print(evaluation)
    if args.output is not None:
        with open(args.output, 'wb') as outfile:
            pickle.dump(evaluation, outfile)


if __name__ == "__main__":
    main()
