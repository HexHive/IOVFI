#!/usr/bin/python3

import json
import sys
import argparse
import re
from decimal import Decimal
import random
import os

functions = list()

added_lines = set()

pointer_types = {15}
long_double_types = {4}
float_types = {2}
MAX_INPUT_LEN = 2*4096
MAX_INPUT_LINES = 1200
MAX_FILE_SIZE=10**9

post_states = dict()
first_funcs = dict()


def output_value(value, output_post = False):
    if value['type'] in pointer_types:
        val = value['precall']
        if output_post:
            if 'postcall' in value:
                val = value['postcall']

        if val is None or val == "":
            val = "nullptr"
        if val[-3:] == "\\00" and int(value['size']) == len(val):
            # This is a string
            return "\"{}\"".format(val)
        return "{}".format(val)
    else:
        val = str(value['value'])
        if value['type'] in long_double_types:
            if val.find(".") < 0:
                val += ".0"
            val += 'l'
        elif value['type'] in float_types:
            if val.find(".") < 0:
                val += ".0"
            val += 'f'
        return "{}".format(val)


def check_post_state(func):
    if func['name'] not in post_states:
        post_states[func['name']] = set()
        first_funcs[func['name']] = func

    if 'value' in func['return']:
        post_state = str(func['return']['value'])
    elif 'postcall' in func['return']:
        post_state = str(func['return']['postcall'])
    else:
        post_state = ''

    for arg in func['args']:
        if 'postcall' in arg:
            post_state += str(arg['postcall'])

    post_states[func['name']].add(post_state)
    # We skipped over the first input, so make sure that we add that in
    # if len(post_states[func['name']]) == 2:
    #     functions.add(first_funcs[func['name']])

    return len(post_states[func['name']]) > 1


def main(included_funcs_path, json_paths):
    if included_funcs_path is None:
        # Match Anything
        match_regex = re.compile(".*")
    else:
        with open(included_funcs_path, "r") as f:
            func_names = set()
            for line in f.readlines():
                line = line.strip()
                if line[0] == '#':
                    continue
                func_names.add("^" + line + "$")
            regex_str = "|".join(func_names)
            match_regex = re.compile(regex_str)

    max_args = -1
    total_error = 0

    uniq_funcs = set()
    for i in range(len(json_paths)):
        # Skip very large files, because it is slooooooow
        if os.path.getsize(json_paths[i]) > MAX_FILE_SIZE:
            print("Skipping {}: File too big".format(json_paths[i]), file=sys.stderr)
            continue

        with open(json_paths[i], "r", errors='ignore') as f:
            line_num = 0
            lines_added = 0

            print("Reading {} (file {} of {})".format(json_paths[i], i + 1, len(json_paths)), file=sys.stderr)
            for line in f.readlines():
                line_num += 1
                line = line.strip()

                try:
                    if line not in added_lines:
                        func = json.loads(line, parse_float=Decimal)['function']
                        if len(line) > MAX_INPUT_LEN:
                            print("Skipping {}:{}; too long".format(json_paths[i], line_num), file=sys.stderr)
                            continue
                        elif match_regex.match(func['name']) is None:
                            print("Skipping {}:{}; Not in function list".format(json_paths[i], line_num), file=sys.stderr)
                            continue

                        if len(func['args']) > max_args:
                            max_args = len(func['args'])

                        if check_post_state(func):
                            lines_added += 1
                            if lines_added > MAX_INPUT_LINES:
                                break

                            functions.append(func)
                            # added_lines.add(line)
                            uniq_funcs.add(func['name'])
                except json.JSONDecodeError as e:
                    print("Invalid json in {}:{}: {}".format(json_paths[i], line_num, e.msg), file=sys.stderr)
                    total_error += 1
                    continue
                except KeyError as e:
                    print("KeyError ({}): {}".format(e, line), file=sys.stderr)
                    continue
    if total_error > 0:
        print("There were {} invalid JSON entries".format(total_error), file=sys.stderr)

    print("Found {} functions".format(len(functions)), file=sys.stderr)

    # Print header
    print("name,return,arg_count", end="")
    if max_args > 0:
        print(",", end="")

    for i in range(max_args):
        print("arg{}".format(i), end="")
        print(",", end="")
    for i in range(max_args):
        print("post{}".format(i), end="")
        if i < max_args - 1:
            print(",", end="")

    print("")

    # Print values
    for func in functions:
        try:
            precall_str = ""
            postcall_str = ""
            precall_str += "{},".format(func['name'])
            if 'return' in func:
                precall_str += "{},{}".format(output_value(func['return'], True), len(func['args']))
                if max_args > 0:
                    precall_str += ","

            for i in range(max_args):
                if i < len(func['args']):
                    precall_str += output_value(func['args'][i])
                    tmp_postcall_str = output_value(func['args'][i], True)
                    postcall_str += tmp_postcall_str
                else:
                    precall_str += "?"
                    postcall_str += "?"

                if i < max_args - 1:
                    precall_str += ","
                    postcall_str += ","

            print("{},{}".format(precall_str, postcall_str))
        except KeyError as e:
            print("ERROR ({}): {}".format(e, str(func)), file=sys.stderr)
            continue

    sys.stdout.flush()
    print("Total unique functions: {}".format(len(uniq_funcs)), file=sys.stderr)
    # print("\n".join(uniq_funcs), file=sys.stderr)
    for uniq_func in uniq_funcs:
        print("test={}".format(uniq_func), file=sys.stderr)

if __name__ == "__main__":
    argp = argparse.ArgumentParser(description="Generate CSV for learning")
    argp.add_argument('--funcs', help="Functions to include in output")
    argp.add_argument('jsons', metavar='/path/to/json', type=str, nargs='+')
    args = argp.parse_args()
    random.seed()
    main(args.funcs, args.jsons)
