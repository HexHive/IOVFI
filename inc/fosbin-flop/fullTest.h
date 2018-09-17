//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_FULLTEST_H
#define FOSBIN_FLOP_FULLTEST_H

#include <experimental/filesystem>
#include <fosbin-flop/testRun.h>
#include <iostream>
#include "binaryDescriptor.h"

namespace fs = std::experimental::filesystem;

namespace fbf {
    class FullTest {
    protected:
        std::vector<std::shared_ptr<fbf::TestRun>> testRuns_;
        BinaryDescriptor binDesc_;

        void parse_descriptor();

    public:
        FullTest(fs::path descriptor);
        ~FullTest();
        void run();
        void output(std::ostream& out);
    };
}

#endif //FOSBIN_FLOP_FULLTEST_H
