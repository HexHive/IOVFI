//
// Created by derrick on 7/6/18.
//

#ifndef FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
#define FOSBIN_FLOP_FUNCTIONIDENTIFIER_H

#include <cstdint>
#include <cstddef>
#include <random>

namespace fbf {
    class FunctionIdentifier {
    public:
        explicit FunctionIdentifier(uintptr_t location, const std::string& functionName);
        explicit FunctionIdentifier();
        virtual ~FunctionIdentifier();

        virtual int run_test();
        uintptr_t get_location();
        const std::string& get_function_name();
        int get_total_tests();
        int get_failed_tests();

        const static size_t BUFFER_SIZE = 32;
        const static int PASS = std::numeric_limits<int>::max();
        const static int FAIL = std::numeric_limits<int>::min();

    protected:
        uintptr_t location_;
        std::string functionName_;
        int totalTests_, failedTests_;

        int rand();
        virtual void evaluate() = 0;
        virtual void setup();

    private:
        std::random_device rd_;
        std::mt19937 mt_;
        std::uniform_int_distribution<int> dist_;
    };

#define FBF_MAJOR_ASSERT(x) {totalTests_++; if(!(x)) { failedTests_++; return; }}
#define FBF_ASSERT(x) {totalTests_++; if(!(x)) { failedTests_++; }}
}

#endif //FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
