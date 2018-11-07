//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_TESTRUN_H
#define FOSBIN_FLOP_TESTRUN_H

#include <memory>
#include "iTestCase.h"

typedef int test_result_t;

namespace fbf {
    class TestRun {
    protected:
        std::shared_ptr<fbf::ITestCase> test_;
        test_result_t result_;
        bool test_has_run_;
        int pid_status_;
        uintptr_t offset_;
        uint64_t execution_result_;

        test_result_t determine_result(pid_t);
        void set_signals();

        void write_to_parent();
        void read_from_child();
        void open_pipe();
        void close_pipe();

        int pipe[2];

        static const unsigned int TIMEOUT;
    public:
        TestRun(std::shared_ptr<fbf::ITestCase> test, uintptr_t offset);
        ~TestRun();
        void run_test();
        void output_results(std::ostream& out);
        test_result_t get_result();
        uintptr_t get_offset();
        uintptr_t get_location();
        const std::string get_test_name();
        bool test_crashed();
        uint64_t get_execution_result();
    };
}

#endif //FOSBIN_FLOP_TESTRUN_H
