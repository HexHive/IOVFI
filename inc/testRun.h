//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_TESTRUN_H
#define FOSBIN_FLOP_TESTRUN_H

#include <identifiers/functionIdentifier.h>
#include <memory>

typedef int test_result_t;

namespace fbf {
    class TestRun {
    protected:
        std::shared_ptr<fbf::FunctionIdentifier> test_;
        test_result_t result_;
        bool test_has_run_;

        test_result_t determine_result(pid_t);
    public:
        TestRun(std::shared_ptr<fbf::FunctionIdentifier> test);
        ~TestRun();
        void run_test();
        void output_results(std::ostream& out);
    };
}

#endif //FOSBIN_FLOP_TESTRUN_H
