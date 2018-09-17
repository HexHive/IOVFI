//
// Created by derrick on 9/17/18.
//

#ifndef FOSBIN_ITESTCASE_H
#define FOSBIN_ITESTCASE_H

#include <string>

namespace fbf {
    class ITestCase {
    public:
        virtual const std::string &get_test_name() = 0;
        virtual int run_test() = 0;
    };
}

#endif //FOSBIN_ITESTCASE_H
