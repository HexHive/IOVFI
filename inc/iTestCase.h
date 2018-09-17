//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_ITESTCASE_H
#define FOSBIN_ITESTCASE_H

#include <string>
#include <limits>

namespace fbf {
    class ITestCase {
    public:
        virtual const std::string get_test_name() = 0;
        virtual int run_test() = 0;

        const static int PASS = std::numeric_limits<int>::max();
        const static int FAIL = std::numeric_limits<int>::min();
    };
}

#endif //FOSBIN_ITESTCASE_H
