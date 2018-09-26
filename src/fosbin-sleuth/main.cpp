#include <iostream>
#include <fosbin-sleuth/fullSleuthTest.h>
#include "fosbin-sleuth.h"

#include "argumentTestCase.h"
#include "binaryDescriptor.h"

#include <boost/program_options.hpp>

int main(int argc, char **argv) {
    uint32_t thread_count;

    namespace po = boost::program_options;

    po::options_description generic("Generic options");
    generic.add_options()
            ("version,v", "Prints version string")
            ("help,h", "Prints this message")
            ("num-threads,t",
             po::value<uint32_t>(&thread_count)->default_value(std::thread::hardware_concurrency()),
             "Number of threads to use")
            ("binary-desc,i", po::value<fs::path>()->required(), "/path/to/binary/descriptor");

    po::positional_options_description p;
    p.add("binary-desc", -1);

    po::variables_map vm;
    try {
        po::store(po::command_line_parser(argc, argv)
                          .options(generic)
                          .positional(p)
                          .run(), vm);
        po::notify(vm);
    } catch (const po::error &e) {
        std::cout << generic << std::endl;
        exit(1);
    }

    if (vm.count("version")) {
        std::cout << SLEUTH_NAME
                  << " v. " << FOSBIN_VERSION_MAJOR << "." << FOSBIN_VERSION_MINOR << std::endl;
        exit(0);
    }

    if (vm.count("help")) {
        std::cout << generic << std::endl;
        exit(0);
    }

    fbf::FullSleuthTest test(vm["binary-desc"].as<fs::path>(), STR_LEN, PTR_LEN, thread_count);
    test.run();
    test.output(std::cout);

    return 0;
}
