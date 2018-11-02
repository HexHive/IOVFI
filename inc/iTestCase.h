//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_ITESTCASE_H
#define FOSBIN_ITESTCASE_H

#include <string>
#include <random>
#include "binaryDescriptor.h"

namespace fbf {
    class ITestCase {
    public:
        ITestCase();
        virtual const std::string get_test_name() = 0;
        virtual int run_test() = 0;
        virtual uintptr_t get_location() = 0;
        virtual void output_result(std::ostream& out);

        const static int PASS = 0;
        const static int FAIL = 1;
        const static int NON_CRASHING = 2;

        /* TODO: overload << operator for easier outputting */

    protected:
        int rand();

    private:
        std::default_random_engine re_;
        std::uniform_int_distribution<int> dist_;
    };
}

#endif //FOSBIN_ITESTCASE_H
