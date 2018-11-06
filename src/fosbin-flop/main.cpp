#include <iostream>
#include "fosbin-flop/fosbin-flop.h"
#include <experimental/filesystem>
#include <fosbin-flop/fullIdentifierTest.h>
#include <commandLineParser.h>

void usage() {
    std::cout << "fosbin-flop <path to binary descriptor>" << std::endl;
}

namespace fs = std::experimental::filesystem;

int main(int argc, char **argv) {
    fbf::CommandLineParser parser(argc, argv, IDENTIFIER_NAME);

    parser.parse();

    try {
        std::cout << "Parsing descriptor...";
        fbf::FullIdentifierTest test(parser["binary-desc"].as<fs::path>(),
                                     parser.get_thread_count());
        std::cout << "Done!" << std::endl;

        test.run();

        test.output(std::cout);
    } catch (std::exception &e) {
        std::cout << "ERROR: " << e.what() << std::endl;
        exit(1);
    }

    return 0;
}
