#include <iostream>
#include "fosbin-sleuth.h"

#include "argumentTestCase.h"
#include "binaryDescriptor.h"

void usage() {
    std::cout << "fosbin-sleuth /path/to/binary/descriptor" << std::endl;
}

int main(int argc, char** argv) {
    std::cout << SLEUTH_NAME
        << " v. " << FOSBIN_VERSION_MAJOR << "." << FOSBIN_VERSION_MINOR
        << " starting. Good luck, Sherlock." << std::endl;

    if(argc != 2) {
        usage();
        exit(1);
    }

    fbf::BinaryDescriptor binDesc(argv[1]);

    size_t num = 0;
    for(uintptr_t location : binDesc.getOffsets()) {
        std::cout << "Testing location " << num << " of "
        << binDesc.getOffsets().size() << "(0x" << std::hex
        << location << std::dec << ")" << std::endl;

        {
            fbf::ArgumentTestCase<void> test;
            std::cout << test.get_arg_types() << std::endl;
            test.test(location);
        }
    }

    return 0;
}
