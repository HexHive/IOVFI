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
             boost::program_options::value<uint32_t>(&thread_count)->default_value(std::thread::hardware_concurrency()),
             "Number of threads to use");
    parser.parse();

    fbf::FullSleuthTest test(parser["binary-desc"].as<fs::path>(), STR_LEN, PTR_LEN, thread_count);
    test.run();
    test.output(std::cout);

    return 0;
}
