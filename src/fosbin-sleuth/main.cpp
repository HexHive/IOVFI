#include <fosbin-sleuth.h>
#include <fullSleuthTest.h>
#include <argumentTestCase.h>
#include <commandLineParser.h>
#include <fuzz/FosbinFuzzer.h>

int main(int argc, char **argv) {
    fbf::CommandLineParser parser(argc, argv, SLEUTH_NAME);
    parser.add_option("syscall", po::value<fs::path>(), "/path/to/syscall/mapping");
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
