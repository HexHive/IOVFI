#include <iostream>
#include <fosbin-sleuth/fullSleuthTest.h>
#include "fosbin-sleuth.h"

#include "argumentTestCase.h"
#include "binaryDescriptor.h"
#include "commandLineParser.h"

int main(int argc, char **argv) {
    uint32_t thread_count;

    fbf::CommandLineParser parser(argc, argv);
//    generic.add_options()
//            ("version,v", "Prints version string")
//            ("help,h", "Prints this message")
//            ("num-threads,t",
//             po::value<uint32_t>(&thread_count)->default_value(std::thread::hardware_concurrency()),
//             "Number of threads to use")
//            ("binary-desc,i", po::value<fs::path>()->required(), "/path/to/binary/descriptor");
    try {
        parser.parse();
    } catch (const boost::program_options::error &e) {
        parser.print_help();
        exit(1);
    }

    if (parser.count("version")) {
        std::cout << SLEUTH_NAME
                  << " v. " << FOSBIN_VERSION_MAJOR << "." << FOSBIN_VERSION_MINOR << std::endl;
        exit(0);
    }

    if (parser.count("help")) {
        parser.print_help();
        exit(0);
    }

    fbf::FullSleuthTest test(vm["binary-desc"].as<fs::path>(), STR_LEN, PTR_LEN, thread_count);
    test.run();
    test.output(std::cout);

    return 0;
}
