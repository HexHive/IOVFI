#!/usr/bin/python3

import sys
import xml.etree.ElementTree as ET
import os

groundTruth = {}


def parse_xml(xml_file_name):
    try:
        tree = ET.parse(xml_file_name)
        root = tree.getroot()
        for memberdef in root.iter("memberdef"):
            if memberdef.get('kind') == "function":
                name = memberdef.find("name").text
                if memberdef.find("param") == None:
                    groundTruth[name] = 0
                else:
                    groundTruth[name] = len(memberdef.findall("param"))
    except:
        sys.stderr.write("error\n")
        return


def usage():
    print("usage: {} /path/to/xml/directory".format(sys.argv[0]))


def main():
    if len(sys.argv) != 2:
        usage()
        exit(1)

    xml_root = sys.argv[1]

    for dir, subdirs, files in os.walk(xml_root):
        for filename in files:
            parse_xml(os.path.join(dir, filename))

    for name, sig in groundTruth.items():
        print("{}={}".format(name, sig))


if __name__ == "__main__":
    main()
