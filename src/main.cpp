#include <iostream>
#include "fosbin-flop.h"
#include <experimental/filesystem>
#include <fullTest.h>

void usage() {
    std::cout << "fosbin-flop <path to binary descriptor>" << std::endl;
}

namespace fs = std::experimental::filesystem;

int main(int argc, char **argv) {
    std::cout << EXE_NAME << " v. " << VERSION_MAJOR << "." << VERSION_MINOR << std::endl;

    if(argc != 2) {
        usage();
        exit(0);
    }
    fs::path descriptor(argv[1]);
    try {
        std::cout << "Parsing descriptor...";
        fbf::FullTest test(descriptor);
        std::cout << "Done!" << std::endl;

        std::cout << "Running tests...";
        test.run();
        std::cout << "Done!" << std::endl;

        std::cout << "Outputting results...";
        test.output(std::cout);
        std::cout << "Done!";
    } catch(std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
        exit(1);
    }

    return 0;
}