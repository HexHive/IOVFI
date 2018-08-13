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
        const std::string& getFunctionName();

        const static size_t BUFFER_SIZE = 32;
        const static int PASS = std::numeric_limits<int>::max();
        const static int FAIL = std::numeric_limits<int>::min();

        virtual const std::string& getName() = 0;

    protected:
        uintptr_t location_;
        std::string functionName_;

        int rand();
        virtual int evaluate() = 0;
        virtual void setup();

    private:
        std::random_device rd_;
        std::mt19937 mt_;
        std::uniform_int_distribution<int> dist_;
    };

#define FBF_ASSERT(x) if(!(x)) { return fbf::FunctionIdentifier::FAIL; }
}

#endif //FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
