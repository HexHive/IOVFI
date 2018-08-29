//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_FULLTEST_H
#define FOSBIN_FLOP_FULLTEST_H

#include <experimental/filesystem>
#include <fosbin-flop/testRun.h>
#include <iostream>
#include <fosbin-flop/binSection.h>

namespace fs = std::experimental::filesystem;

namespace fbf {
    class FullTest {
    protected:
        std::vector<std::shared_ptr<fbf::TestRun>> testRuns_;
        fs::path descriptor_, bin_path_;
        BinSection text_;
        BinSection data_;
        BinSection bss_;

        void parse_descriptor();
        uintptr_t parse_offset(std::string& offset);

    public:
        FullTest(fs::path descriptor);
        ~FullTest();
        void run();
        void output(std::ostream& out);
    };
}

#endif //FOSBIN_FLOP_FULLTEST_H
