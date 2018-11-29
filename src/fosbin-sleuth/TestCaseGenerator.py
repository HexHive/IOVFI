#!/usr/bin/python3

import sys

# NB: THESE TYPES CANNOT HAVE SPACES!
supported_types = {
    'int': '0',
    'double': '0.0',
    'void*': 'buffers[{}]',
    'float': '0.0f',
    'long double': '0.0l'
}

# Number of args we support
max_args = 5

sigs = []

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

    max_arity = max_args - 1

    for type in range(0, len(supported_types)):
        for arity in range(0, max_arity):
            for template in sigs[type][arity]:
                ptr_count = 0
                func_input = list()
                for ctype in template:
                    if ctype == "void*":
                        func_input.append(supported_types[ctype].format(ptr_count))
                        ptr_count += 1
                    else:
                        func_input.append(supported_types[ctype])

                if "void*" in template:
                    # Make sure that there is a pointer in the arguments if we are fuzzing a void function
                    print("make_fuzzer<void, {}>({});".format(", ".join(template), ", ".join(func_input)))

    for type in range(0, len(supported_types)):
        for arity in range(0, max_arity):
            for template in sigs[type][arity]:
                ptr_count = 0
                func_input = list()
                for ctype in template[1:]:
                    if ctype == "void*":
                        func_input.append(supported_types[ctype].format(ptr_count))
                        ptr_count += 1
                    else:
                        func_input.append(supported_types[ctype])

                print("make_fuzzer<{}>({});".format(", ".join(template), ", ".join(func_input)))



if __name__ == "__main__":
    main()
