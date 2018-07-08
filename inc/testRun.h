//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_TESTRUN_H
#define FOSBIN_FLOP_TESTRUN_H

#include <functionIdentifier.h>
#include <memory>

namespace fbf {
    class TestRun {
        std::shared_ptr<fbf::FunctionIdentifier> test_;
        int result_;
        bool test_has_run_;

    public:
        TestRun(std::shared_ptr<fbf::FunctionIdentifier> test);
        ~TestRun();
        void run_test();
        void output_results(std::ostream& out);
    };
}

#endif //FOSBIN_FLOP_TESTRUN_H
