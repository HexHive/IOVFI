#!/usr/bin/python3

import json
import sys

functions = []

added_lines = set()

pointer_types = {15}
MAX_INPUT_LEN = 1024


def output_value(value):
    if value['type'] in pointer_types:
        if value['precall'][-3:] == "\\00" and int(value['size']) == len(value['precall']):
            # This is a string
            return "\"{}\"".format(value['precall'])
        return "{}".format(value['precall'])
    else:
        return "{}".format(value['value'])


def main():
    if len(sys.argv) < 2:
        print("gen-csv.py /path/to/json ...", file=sys.stderr)
        exit(1)

    max_args = -1
    total_error = 0

    for i in range(1, len(sys.argv)):
        with open(sys.argv[i], "r", errors='ignore') as f:
            line_num = 0
            print("Reading {} (file {} of {})".format(sys.argv[i], i, len(sys.argv) - 1), file=sys.stderr)
            for line in f.readlines():
                line_num += 1
                line = line.strip()
                start_idx = line.find("{ \"function\":")
                if start_idx >= 0:
                    line = line[start_idx:]
                    end_idx = line.find("] }")
                    line = line[:end_idx + len("] }")]
                    line += "}"

                    try:
                        if line not in added_lines:
                            func = json.loads(line)['function']
                            if len(line) > MAX_INPUT_LEN:
                                print("Skipping {}:{}; too long".format(sys.argv[i], line_num), file=sys.stderr)
                                continue

                            if len(func['args']) > max_args:
                                max_args = len(func['args'])

                            functions.append(func)
                            added_lines.add(line)
                    except json.JSONDecodeError as e:
                        print("Invalid json in {}:{}: {}".format(sys.argv[i], line_num, e.msg), file=sys.stderr)
                        total_error += 1
                        continue
                    except KeyError as e:
                        print("KeyError ({}): {}".format(e, line),
                                file=sys.stderr)
    if total_error > 0:
        print("There were {} invalid JSON entries".format(total_error), file=sys.stderr)

    print("Found {} functions".format(len(functions)), file=sys.stderr)

    # Print header
    print("name,return,arg_count", end="")
    if max_args > 0:
        print(",", end="")

    for i in range(max_args):
        print("arg{}".format(i), end="")
        if i < max_args - 1:
            print(",", end="")

    print("")

    # Print values
    for func in functions:
        try:
            print("{},".format(func['name']), end="")
            if 'return' in func:
                print("{},{}".format(output_value(func['return']), len(func['args'])), end="")
                if max_args > 0:
                    print(",", end="")

            for i in range(max_args):
                if i < len(func['args']):
                    print(output_value(func['args'][i]), end="")
                else:
                    print("?", end="")

                if i < max_args - 1:
                    print(",", end="")
        except KeyError as e:
            print("ERROR ({}): {}".format(e, str(func)), file=sys.stderr)
            continue
            #exit(1)
        print("")


if __name__ == "__main__":
    main()
