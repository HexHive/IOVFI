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


class TreeEvaluation:
    def __init__(self, tree_path):
        self.tree_path = os.path.abspath(tree_path)
        self.specificities = list()
        self.recalls = list()
        self.accuracies = list()
        self.precisions = list()
        self.guess_paths = list()

    def add_evaluation(self, guess_path, true_pos, true_neg, incorrect):
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

    def __str__(self):
        if len(self.accuracies) > 1:
            avg = statistics.mean(self.accuracies)
            stddev = statistics.stdev(self.accuracies)
            median = statistics.mean(self.accuracies)
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
            median = statistics.mean(self.recalls)
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
            median = statistics.mean(self.specificities)
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
            median = statistics.mean(self.precisions)
        elif len(self.precisions) == 1:
            avg = self.precisions[0]
            median = self.precisions[0]
            stddev = 0
        else:
            raise AssertionError("No guesses provided")

        result += "Average Precision: {} +- {}\n".format(avg, stddev)
        result += "Median Accuracy: {}".format(median)

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

            true_pos, true_neg, incorrect = tu.get_evaluation(dtree, guesses, equivalences)
            evaluation.add_evaluation(guessLine, true_pos, true_neg, incorrect)

    print(evaluation)
    if args.output is not None:
        with open(args.output, 'wb') as outfile:
            pickle.dump(evaluation, outfile)


if __name__ == "__main__":
    main()
