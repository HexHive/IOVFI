//
// Created by derrick on 10/7/18.
//

#ifndef FOSBIN_ARGUMENTCOUNTTEST_H
#define FOSBIN_ARGUMENTCOUNTTEST_H

#include "iTestCase.h"
#include <capstone/capstone.h>

namespace fbf {
    class ArgumentCountTestCase : public ITestCase {
    public:
        ArgumentCountTestCase(uintptr_t location, size_t size);
        virtual ~ArgumentCountTestCase();

        virtual const std::string get_test_name();
        virtual int run_test();
        virtual uint64_t get_value();
    protected:
        uintptr_t location_;
        size_t size_;
        uint8_t arg_count_;
        csh handle_;
    };
}


#endif //FOSBIN_ARGUMENTCOUNTTEST_H
