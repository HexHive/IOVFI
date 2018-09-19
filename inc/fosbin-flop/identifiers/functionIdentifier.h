//
// Created by derrick on 7/6/18.
//

#ifndef FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
#define FOSBIN_FLOP_FUNCTIONIDENTIFIER_H

#include <cstdint>
#include <cstddef>
#include <random>
#include "iTestCase.h"

namespace fbf {
    class FunctionIdentifier : public ITestCase {
    public:
        explicit FunctionIdentifier(uintptr_t location, const std::string& functionName);
        explicit FunctionIdentifier();
        virtual ~FunctionIdentifier();

        virtual int run_test();
        uintptr_t get_location();
        const std::string get_test_name();
        int get_total_tests();
        int get_failed_tests();

        const static size_t BUFFER_SIZE = 32;
        const static int MAX_FAIL_RATE;

    protected:
        uintptr_t location_;
        std::string functionName_;
        int totalTests_, failedTests_;

        virtual int evaluate() = 0;
        virtual void setup();
    };

#define FBF_MAJOR_ASSERT(x) {totalTests_++; if(!(x)) { failedTests_++; return fbf::ITestCase::FAIL; }}
#define FBF_ASSERT(x) {totalTests_++; if(!(x)) { failedTests_++; }}
}

#endif //FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
