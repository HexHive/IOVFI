#!/usr/bin/python3

import sys
import xml.etree.ElementTree as ET
import os

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
    'long int': 'int'
}

def usage():
    print("usage: {} /path/to/results /path/to/xml/directory".format(sys.argv[0]))


def transform_arg(arg):
    arg = arg.replace("(", "").replace(")", "").replace("const", "")

    if arg == "":
        return "void"

    if contains_pointer(arg):
        return "void*"

    if arg.find("struct") > 0:
        tokens = arg.split()
        return tokens[0] + "_" + tokens[1]
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
                for param in memberdef.find("argsstring").text.split(", "):
                    groundTruth[name].append(transform_arg(param))
                if len(groundTruth[name]) == 0:
                    groundTruth[name].append("void")

    except:
        sys.stderr.write("error\n")
        return


def contains_pointer(arg):
    if arg is None:
        return False

    return arg.find("*") >= 0


def main():
    if len(sys.argv) != 3:
        usage()
        exit(1)

    xml_root = sys.argv[2]

    for dir, subdirs, files in os.walk(xml_root):
        for filename in files:
            parse_xml(os.path.join(dir, filename))

    with open(sys.argv[1], "r", errors='ignore') as guesses:
        syms = set()

        for guess in guesses.readlines():
            index = guess.find('=')
            if index > 0 and len(guess) < 40 + len("MISSING "):
                sym = guess[index + 1:]
                syms.add(sym.strip())
                continue

            index = guess.find(":")
            if index < 0:
                continue

            name = guess[0:index]
            if name in syms:
                syms.remove(name)

            if name in groundTruth:
                transformedArgs = []
                for arg in groundTruth[name]:
                    transformedArgs.append(arg)

                finalArgs = "< " + " ".join(transformedArgs) + " >"
                if guess.find("CRASH") >= 0:
                    print("0\t0\t0\t{}: CRASHED <-> {}".format(name, finalArgs))
                    continue
                else:
                    print("{}\t{}\t{}\t{}: {} <-> {}".format(guess.count("<"), finalArgs == guess[index+1:].strip(), guess[index+1:].find(finalArgs) > 0, name, guess[index+1:].strip(), finalArgs))

        for sym in syms:
            print("MISSING " + sym)

if __name__ == "__main__":
    main()