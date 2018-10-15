#!/usr/bin/python3

import json
import sys

MAX_TESTS = 10

functions = {}

function_names = {}

type_ids = {
    0 : "void",
    1 : "short",
    2 : "float",
    3 : "double",
    4 : "long long",
    5 : "long long",
    6 : "",
    7 : "",
    8 : "",
    9 : "",
    10: "",
    11: "int",
    12: "",
    13: "",
    14: "",
    15: "int*",
    16: ""
}


def parse_function_names(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.strip()
            if line != "":
                tokens = line.split("=")
                function_names[tokens[0]] = tokens[1]


def usage():
    print("{} <path to json> <path to function name mapping>".format(sys.argv[0]))


def get_class_name(func):
    func_name = get_func_name(func)

    return "Func" + func_name.capitalize() + "Identifier"


def get_func_name(funcaddr):
    return function_names[funcaddr]


def output_header(func):
    print("#include <identifiers/functionIdentifier.h>")
    print("#include <identifiers/identifierRegistrar.h>\n")
    print("namespace fbf {")

    idname = get_class_name(func)
    func_name = get_func_name(func)

    print("\tclass {} : public FunctionIdentifier {{".format(idname))
    print("\tpublic:")
    print("\t\texplicit {}(uintptr_t location);".format(idname))
    print("\t\texplicit {}();".format(idname))
    print("\t\t~{}();".format(idname))
    print("\t\tint evaluate() override;")
    print("\t\tvoid setup() override;")

    print("\t};\n")
    print("\tstatic IdentifierRegistrar<{}> registrar_{}(\"{}\");\n}}".format(idname, func_name, func_name))


def output_type(argtype):
    return type_ids[argtype["type"]]


def gen_func_cast(func):
    test = functions[func][0]
    args = test["args"]
    retval = test["return"]

    out = "auto func = reinterpret_cast<"
    out += output_type(retval)
    out += " (*)("
    idx = 0
    while idx < len(args):
        arg = args[idx]
        out += output_type(arg)
        if idx != len(args) - 1:
            out += ", "
        idx += 1

    out += ")>(location_);"
    return out


def gen_test_str(test):
    out = "FBF_ASSERT("

    retval = test["return"]
    args = test["args"]

    out += str(retval["value"])
    out += " == func("
    idx = 0
    while idx < len(args):
        arg = args[idx]
        out += str(arg["value"])
        if idx != len(args) - 1:
            out += ", "
        idx += 1
    out += "));"
    return out


def output_definition(func):
    idname = get_class_name(func)
    funcname = get_func_name(func)
    print("#include <identifiers/fbf-{}.h>".format(idname))
    print("#include <cstring>\n")
    print("fbf::{}::{}(uintptr_t location) :\n\tFunctionIdentifier(location, \"{}\") {{}}\n".format(idname, idname, funcname))
    print("fbf::{}::{}() :\n\tFunctionIdentifier() {{}}\n".format(idname, idname))
    print("fbf::{}::~{}() = default;\n".format(idname, idname))
    print("void fbf::{}::setup() {{ }}\n".format(idname))
    print("int fbf::{}::evaluate() {{".format(idname))
    print("\t" + gen_func_cast(func))

    tests = functions[func]
    for test in tests:
        print("\t" + gen_test_str(test))

    print("\treturn FunctionIdentifier::PASS;\n}")


def output_identifier():
    for func in functions:
        output_header(func)
        output_definition(func)


def main():
    if len(sys.argv) < 3:
        usage()
        exit(1)

    parse_function_names(sys.argv[2])

    file = open(sys.argv[1])
    try:
        decoded = json.load(file)
        for funcent in decoded['functions']:
            func = funcent['function']
            if func['addr'] not in function_names:
                continue

            if func['addr'] in functions and len(functions[func['addr']]) > MAX_TESTS:
                continue

            if func['addr'] not in functions:
                functions[func["addr"]] = []

            functions[func['addr']].append(func)
        output_identifier()

    except ValueError as e:
        print("Value error: ", e)
        file.close()
        exit(2)
    except KeyError as e:
        print("Key error: ", e)
        file.close()
        exit(2)
    except TypeError as e:
        print("Type error: ", e)
        file.close()
        exit(2)

    file.close()


if __name__ == "__main__":
    main()
