#include <fosbin-sleuth.h>
#include <fullArityTest.h>
#include <argumentTestCase.h>
#include <commandLineParser.h>
#include <fuzz/FullFuzzTest.h>

int main(int argc, char **argv) {
    fbf::CommandLineParser parser(argc, argv, SLEUTH_NAME);
    parser.add_option("syscall", po::value<fs::path>(), "/path/to/syscall/mapping");
    parser.add_option(
            "arg-counts,a",
            po::value<fs::path>(),
            "/path/to/argument/counts"
    );
    parser.parse();

    if (parser.count("arg-counts")) {
        fbf::FullFuzzTest test(parser["binary-desc"].as<fs::path>(), parser["arg-counts"].as<fs::path>(), parser
                .get_thread_count());
        test.run();
        test.output(std::cout);
    } else {
        if (parser.count("syscall")) {
            fbf::FullArityTest test(parser["binary-desc"].as<fs::path>(), parser["syscall"].as<fs::path>(), STR_LEN,
                                    PTR_LEN, parser.get_thread_count());
            test.run();
            test.output(std::cout);
        } else {
            fbf::FullArityTest test(parser["binary-desc"].as<fs::path>(), STR_LEN, PTR_LEN, parser.get_thread_count());
            test.run();
            test.output(std::cout);
        }
    }

    return 0;
}
