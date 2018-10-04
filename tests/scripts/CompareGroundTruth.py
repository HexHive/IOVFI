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
                for param in memberdef.find("argsstring").text.split(", "):
                    arg = transform_arg(param)
                    groundTruth[name].append(transform_arg(param))
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

    sym_regex = re.compile("(0[Xx][0-9A-Fa-f]+)=([A-Za-z0-9_]+)")
    guess_regex = re.compile("([0-9A-Za-z_]+):([a-zA-Z* <>]+)")
    with open(sys.argv[1], "r", errors='replace') as guesses:
        syms = {}
        addr_map = {}

        for guess in guesses.readlines():
            # Skip over junk output from the test run, and only get <addr>=<sym>
            sym_match = sym_regex.match(guess)
            if sym_match:
                sym = sym_match.group(2)
                addr = sym_match.group(1)
                if addr not in syms:
                    syms[addr] = set()
                syms[addr].add(sym)
                addr_map[sym] = addr
                continue

            guess_match = guess_regex.match(guess)
            if not guess_match:
                continue

            name = guess_match.group(1).strip()
            func_guesses = guess_match.group(2).strip()

            addr = addr_map[name]

            for name2 in syms[addr]:
                if name2 in groundTruth:
                    transformedArgs = []
                    for arg in groundTruth[name2]:
                        transformedArgs.append(arg)

                    finalArgs = " ".join(transformedArgs)
                    if transformedArgs[0] == "void":
                        finalArgCount = 0
                    else:
                        finalArgCount = len(transformedArgs)

                    for sym in syms[addr]:
                        if guess.find("CRASH") >= 0:
                            print("0\t0\t0\t{}: CRASHED <-> < {} > {}".format(sym, finalArgs, finalArgCount))
                            continue
                        else:
                            print("{}\t{}\t{}\t{}: {} <-> < {} > {}".format(func_guesses.count("<"),
                                                                            "< " + finalArgs + " >" == func_guesses,
                                                                            func_guesses.find("< " + finalArgs + " >") >= 0,
                                                                            sym, func_guesses, finalArgs,
                                                                            finalArgCount))
            syms.pop(addr)

        for addr in syms:
            print("MISSING " + str(syms[addr]))


if __name__ == "__main__":
    main()
