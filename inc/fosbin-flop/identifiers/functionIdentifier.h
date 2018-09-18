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

        const static size_t BUFFER_SIZE = 32;

    protected:
        uintptr_t location_;
        std::string functionName_;

        virtual int evaluate() = 0;
        virtual void setup();
    };

#define FBF_ASSERT(x) if(!(x)) { return fbf::ITestCase::FAIL; }
}

#endif //FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
