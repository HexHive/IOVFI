#!/usr/bin/python3

import sys

# NB: THESE TYPES CANNOT HAVE SPACES!
supported_types = {
    'int': 'testInts[{}]',
    # 'double': 'testDbls[{}]',
    # 'char*': 'testStrs[{}]',
    'void*': '&testPtrs[{}]',
}

# Number of args we support
max_args = 5

# Number of args passed into the function
total_args = 8

sigs = []

INVALID_TYPE = "uintptr_t"
INVALID_VALUE = "getRandLong()"
INVALID_ARGUMENT = "({}){}".format(INVALID_TYPE, INVALID_VALUE)
DEFAULT_RET_TYPE = "void*"


def main():
    for index in range(0, len(supported_types)):
        sigs.append([])
        sigs[index].append([])

    i = 0
    for type in supported_types.keys():
        sigs[i][0].append([type])
        i += 1

    for index in range(0, len(supported_types)):
        for arg_num in range(1, max_args):
            sigs[index].append([])
            i = 0
            for prev in sigs[index][arg_num - 1]:
                for t in supported_types.keys():
                    sigs[index][arg_num].append([])
                    newsig = prev.copy()
                    newsig.append(t)
                    sigs[index][arg_num][i] = newsig
                    i += 1

    typeStr = ""
    for x in range(0, total_args):
        typeStr += "{}, ".format(INVALID_TYPE)

    typeStr = typeStr[:-2]
    print("{{\n\tstd::tuple<{}> t;".format(typeStr))

    print("\tstd::vector<std::string> l;")
    for i in range(0, total_args):
        print("\tstd::get<{}>(t) = {};".format(i, INVALID_ARGUMENT));

    print("\tstd::shared_ptr<fbf::ArgumentTestCase<{}, {}>> v = ".format(DEFAULT_RET_TYPE, typeStr))
    print("\tstd::make_shared<fbf::ArgumentTestCase<{}, {}>>(location, t, l, binDesc_);".format(DEFAULT_RET_TYPE, typeStr))
    print("\ttestRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));\n}")

    for index in range(0, len(supported_types)):
        allsigs = sigs[index]
        for arg_num in range(0, max_args):
            siglist = allsigs[arg_num]
            for sig in siglist:
                typeStr = ", ".join(sig)
                for filler in range(arg_num, total_args):
                    typeStr += ", {}".format(INVALID_TYPE)

                print("{{\n\tstd::tuple<{}> t;".format(typeStr))
                argTypeStr = "\", \"".join(sig)
                print("\tstd::vector<std::string> s = {{\"{}\"}};".format(argTypeStr))

                i = 0
                type_counts = {}
                for type in supported_types.keys():
                    type_counts[type] = 0
                type_counts[INVALID_TYPE] = 0

                for t in typeStr.split(', '):
                    if t == INVALID_TYPE:
                        val = INVALID_ARGUMENT
                    else:
                        val = supported_types[t]
                    tupleStr = "\tstd::get<{}>(t) = {};".format(i, val)
                    tupleStr = tupleStr.format(type_counts[t])
                    type_counts[t] = type_counts[t] + 1

                    print(tupleStr)
                    i += 1

                print("\tstd::shared_ptr<fbf::ArgumentTestCase<{}, {}>> v =".format(DEFAULT_RET_TYPE, typeStr))
                print("\t\tstd::make_shared<fbf::ArgumentTestCase<{}, {}>>(location, t, s, binDesc_);".format(DEFAULT_RET_TYPE, typeStr))
                print("\ttestRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));")
                print("}")


if __name__ == "__main__":
    main()
