#include <iostream>
#include <fosbin-sleuth/fullSleuthTest.h>
#include "fosbin-sleuth.h"

#include "argumentTestCase.h"
#include "binaryDescriptor.h"
#include "commandLineParser.h"

int main(int argc, char **argv) {
    uint32_t thread_count;

    fbf::CommandLineParser parser(argc, argv, SLEUTH_NAME);

    parser.add_option("num-threads,t",
                      boost::program_options::value<uint32_t>(&thread_count)->default_value(
                              std::thread::hardware_concurrency()),
                      "Number of threads to use");
    parser.add_option("syscall", boost::program_options::value<fs::path>(), "/path/to/syscall/mapping");
    parser.parse();
    if (thread_count < 0) {
        thread_count = 1;
    } else if (thread_count > std::thread::hardware_concurrency()) {
        thread_count = std::thread::hardware_concurrency();
    }

    if (parser.count("syscall")) {
        fbf::FullSleuthTest test(parser["binary-desc"].as<fs::path>(), parser["syscall"].as<fs::path>(), STR_LEN,
                                 PTR_LEN, thread_count);
        test.run();
        test.output(std::cout);
    } else {
        fbf::FullSleuthTest test(parser["binary-desc"].as<fs::path>(), STR_LEN, PTR_LEN, thread_count);
        test.run();
        test.output(std::cout);
    }

    return 0;
}
