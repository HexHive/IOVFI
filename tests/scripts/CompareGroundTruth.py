#!/usr/bin/python3

import sys
import xml.etree.ElementTree as ET
import os
import re

groundTruth = {}

type_map = {
    'long': 'int',
    'const char *': "void*",
    'size_t': 'int',
    'locale_t': 'int',
    'unsigned': 'int',
    'off_t': 'int',
    'unsigned long': 'int',
    'long long': 'int',
    'wint_t': 'int',
    'wchar_t': 'int',
    'wctype_t': 'int',
    'uint32_t': 'int',
    'char16_t': 'int',
    'socklen_t': 'int',
    'dev_t': 'int',
    'mode_t': 'int',
    'clockid_t': 'int',
    'uid_t': 'int',
    'gid_t': 'int',
    'pid_t': 'int',
    'intmax_t': 'int',
    'wctrans_t': 'void*',
    'key_t': 'int',
    'eventfd_t': 'int',
    'nfds_t': 'int',
    'intptr_t': 'void*',
    'nl_catd': 'void*',
    'iconv_t': 'void*',
    'nl_item': 'int',
    'uintptr_t': 'void*',
    'id_t': 'int',
    'mqd_t': 'int',
    'uint16_t': 'int',
    'in_addr_t': 'int',
    'ns_sect': 'int',
    'idtype_t': 'int',
    'ssize_t': 'int',
    'speed_t': 'int',
    'thrd_t': 'int',
    'thrd_start_t': 'void*',
    'tss_dtor_t': 'void*',
    'time_t': 'int',
    'timer_t': 'void*',
    'short': 'int',
    'char32_t': 'int',
    'long': 'int',
    'tss_t': 'int',
    'long int': 'int',
    "pthread_t": "void*"
}


def usage():
    print("usage: {} /path/to/results /path/to/xml/directory".format(sys.argv[0]))


def transform_arg(arg):
    arg = arg.replace("(", "").replace(")", "").replace("const", "").strip()

    if arg == "":
        return "void"

    if contains_pointer(arg):
        return "void*"

    if arg.find("struct") >= 0:
        return arg.replace(" ", "_")
    elif arg.find("union") >= 0:
        return arg.replace(" ", "_")
    elif len(arg.split()) > 1:
        arg = arg.split()[0]

    if arg in type_map:
        return type_map[arg]

    return arg


def parse_xml(xml_file_name):
    try:
        tree = ET.parse(xml_file_name)
        root = tree.getroot()
        for memberdef in root.iter("memberdef"):
            if memberdef.get('kind') == "function":
                name = memberdef.find("name").text
                groundTruth[name] = []
                # for param in memberdef.find("argsstring").text.split(", "):
                #     groundTruth[name].append(transform_arg(param))
                groundTruth[name].append(memberdef.find("argsstring").text)
                if len(groundTruth[name]) == 0:
                    groundTruth[name].append("void")

    except:
        sys.stderr.write("error\n")
        return


def contains_pointer(arg):
    if arg is None:
        return False

    return arg.find("*") >= 0 or arg.find("[") >= 0


def main():
    if len(sys.argv) != 3:
        usage()
        exit(1)

    xml_root = sys.argv[2]

    for dir, subdirs, files in os.walk(xml_root):
        for filename in files:
            parse_xml(os.path.join(dir, filename))

    guess_regex = re.compile("Function ([0-9A-Za-z_]+) has ([0-9]+) argument")
    crash_regex = re.compile("Function ([0-9A-Za-z_]+) CRASHED")
    with open(sys.argv[1], "r", errors='replace') as guesses:
        for guess in guesses.readlines():
            guess_match = guess_regex.match(guess)
            crash_match = crash_regex.match(guess)
            if guess_match:
                name = guess_match.group(1).strip()
                arg_count_guess = int(guess_match.group(2).strip())
            elif crash_match:
                name = crash_match.group(1).strip()
            else:
                continue


            if name in groundTruth:
                finalArgs = groundTruth[name][0]
                if finalArgs == "(void)" or finalArgs == "()":
                    finalArgCount = 0
                elif finalArgs.find("...") >= 0:
                    finalArgCount = 6
                else:
                    finalArgCount = finalArgs.count(',') + 1

                if crash_match:
                    print("False\t{}: CRASHED <-> < {} >".format(name, finalArgs))
                    continue
                else:
                    print("{}\t{}: {} <-> < {} >".format(arg_count_guess == finalArgCount, name, arg_count_guess, finalArgs))


if __name__ == "__main__":
    main()
