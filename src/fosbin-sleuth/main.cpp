#include <iostream>
#include <fosbin-sleuth/fullSleuthTest.h>
#include "fosbin-sleuth.h"

#include "argumentTestCase.h"
#include "binaryDescriptor.h"
#include "commandLineParser.h"

int main(int argc, char **argv) {
    fbf::CommandLineParser parser(argc, argv, SLEUTH_NAME);
    parser.add_option("syscall", boost::program_options::value<fs::path>(), "/path/to/syscall/mapping");
    parser.parse();

    if (parser.count("syscall")) {
        fbf::FullSleuthTest test(parser["binary-desc"].as<fs::path>(), parser["syscall"].as<fs::path>(), STR_LEN,
                                 PTR_LEN, parser.get_thread_count());
        test.run();
        test.output(std::cout);
    } else {
        fbf::FullSleuthTest test(parser["binary-desc"].as<fs::path>(), STR_LEN, PTR_LEN, parser.get_thread_count());
        test.run();
        test.output(std::cout);
    }

    return 0;
}
