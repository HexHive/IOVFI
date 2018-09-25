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
    'socklen_t': 'int'
}

def usage():
    print("usage: {} /path/to/results /path/to/xml/directory".format(sys.argv[0]))


def transform_arg(arg):
    if contains_pointer(arg):
        return "void*"

    arg = arg.replace("(", "").replace(")", "").replace("const", "")

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

    with open(sys.argv[1], "r") as guesses:
        for guess in guesses.readlines():
            index = guess.find(":")
            name = guess[0:index]
            if name in groundTruth:
                transformedArgs = []
                for arg in groundTruth[name]:
                    transformedArgs.append(arg)

                if len(transformedArgs) == 0:
                    transformedArgs.append("void")

                print("{}: {} <-> < {} >".format(name, guess[index+1:].strip(), " ".join(transformedArgs)))


if __name__ == "__main__":
    main()