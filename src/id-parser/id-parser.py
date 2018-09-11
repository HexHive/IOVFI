import json
import sys

functions = {}


def usage():
    print("{} <path to json> [<path to json>...]")


def output_identifier():
    for func in functions:
        tests = functions[func]
        print("#include <identifiers/functionIdentifier.h>")
        print("#include <identifiers/identifierRegistrar.h>\n")
        print("namespace fbf {")

        idname = "Func" + func + "Identifier"

        print("\tclass {} : public FunctionIdentifier {{".format(idname))
        print("\tpublic:")
        print("\t\texplicit {}(uintptr_t location);".format(idname))
        print("\t\texplicit {}();".format(idname))
        print("\t\t~{}();".format(idname))
        print("\t\tint evaluate() override;")
        print("\t\tvoid setup() override;")

        # TODO: add in test generation

        print("\t};\n")
        print("\tstatic IdentifierRegistrar<{}> registrar_{}(\"{}\");\n}}".format(idname, func, func))


def main():
    if len(sys.argv) < 2:
        usage()
        exit(1)

    file = open(sys.argv[1])
    try:
        decoded = json.load(file)
        for funcent in decoded['functions']:
            func = funcent['function']
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
