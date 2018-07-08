//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_FULLTEST_H
#define FOSBIN_FLOP_FULLTEST_H

#include <experimental/filesystem>
#include <testRun.h>
#include <iostream>

namespace fs = std::experimental::filesystem;

namespace fbf {
    class FullTest {
        std::vector<std::unique_ptr<fbf::TestRun>> testRuns_;
        fs::path descriptor_, bin_path_;
        void parse_descriptor();

    public:
        FullTest(fs::path descriptor);
        ~FullTest();
        void run();
        void output(std::ostream& out);
    };
}

#endif //FOSBIN_FLOP_FULLTEST_H
