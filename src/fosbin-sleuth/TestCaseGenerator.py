#!/usr/bin/python3

import sys

supported_types = {
    'int': 'testInt',
    'double': 'testDbl',
    'char*': 'testStr',
    'void*': 'testPtr'
}

max_args = 6

sigs = []

def main():
    for index in range(0, len(supported_types)):
        sigs.append([])
        sigs[index].append([])

    i = 0
    for type in supported_types.keys():
        sigs[i][0].append(type)
        i += 1

    for index in range(0, len(supported_types)):
        for arg_num in range(0, max_args * len(supported_types)):
            i = len(sigs[index])
            for type in supported_types.keys():
                sigs[index].append([])
                sigs[index][i] = sigs[index][arg_num] + [type]
                i += 1

    for index in range(0, len(supported_types)):
        siglist = sigs[index]
        for sig in siglist:
            typeStr = ", ".join(sig)
            print("{{\n\tstd::tuple<{}> t;".format(typeStr))
            argTypeStr = "\", \"".join(sig);
            print("\tstd::vector<std::string> s = {{\"{}\"}};".format(argTypeStr))
            i = 0
            for t in sig:
                print("\tstd::get<{}>(t) = {};".format(i, supported_types[t]))
                i += 1

            print("\tstd::shared_ptr<fbf::ArgumentTestCase<void, {}>> v =".format(typeStr))
            print("\t\tstd::make_shared<fbf::ArgumentTestCase<void, {}>>(location, t, s);".format(typeStr))
            print("\ttestRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));")
            print("}")

if __name__ == "__main__":
    main()