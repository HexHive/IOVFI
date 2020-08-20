import argparse
import re

from sklearn.metrics import f1_score


def compute_accuracy(bindiff):
    functionMatchRegex = "([0-9A-Fa-f]+)\s+([" \
                         "0-9A-Fa-f]+)\s+\d\.?\d*\s+\d\.?\d*\s+\d\.?\d*\s+\d" \
                         "\.?\d*\s+\d\.?\d*\s+\d\.?\d*\sfunction:.+\"(" \
                         "\w+)\"\s+\"(\w+)\""
    functionMatch = re.compile(functionMatchRegex)
    unmatchedRegex = "([0-9A-Fa-f]+)\s+\d+\s+\d+\s+(\w+)"
    unmatchedMatch = re.compile(unmatchedRegex)

    reading_unmatched_primary = False
    reading_unmatched_secondary = False

    primary_syms = set()
    secondary_syms = set()
    predictions = list()
    truths = list()
    unmatched_secondary = list()

    unknown = "@@UNKNOWN@@"

    with open(bindiff, 'r') as f:
        for line in f.readlines():
            match = functionMatch.match(line)
            # if not match and not reading_unmatched_primary and not \
            #         reading_unmatched_secondary:
            #     print(line)

            if match:
                primary_syms.add(match.group(3).strip())
                secondary_syms.add(match.group(4).strip())
                predictions.append(match.group(4).strip())
                truths.append(match.group(3).strip())
            elif re.search("unmatched primary", line):
                reading_unmatched_primary = True
                reading_unmatched_secondary = False
            elif re.search("unmatched secondary", line):
                reading_unmatched_secondary = True
                reading_unmatched_primary = False
            elif reading_unmatched_primary:
                match = unmatchedMatch.match(line)
                if match:
                    primary_syms.add(match.group(2).strip())
            elif reading_unmatched_secondary:
                match = unmatchedMatch.match(line)
                if match:
                    secondary_syms.add(match.group(2).strip())
                    unmatched_secondary.append(match.group(2).strip())

        for unmatched_sym in unmatched_secondary:
            predictions.append(unknown)
            if unmatched_sym in primary_syms:
                truths.append(unmatched_sym)
            else:
                truths.append(unknown)

        # for i in range(len(truths)):
        #     print("{} <--> {}".format(truths[i], predictions[i]))

        print(f1_score(truths, predictions, average='micro'))


def main():
    parser = argparse.ArgumentParser(description="Computes BinDiff Accuracy")
    parser.add_argument('-b', '--bindiffLog', required=True)
    args = parser.parse_args()

    compute_accuracy(args.bindiffLog)


if __name__ == "__main__":
    main()