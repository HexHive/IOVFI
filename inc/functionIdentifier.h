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
        explicit FunctionIdentifier(uintptr_t location);

        virtual ~FunctionIdentifier();

        virtual int run_test();

        uintptr_t get_location();

        const static size_t BUFFER_SIZE = 32;

    protected:
        uintptr_t location_;

        int rand();

        virtual int evaluate() = 0;

        virtual void setup();

    private:
        std::random_device rd_;
        std::mt19937 mt_;
        std::uniform_int_distribution<int> dist_;
    };

#define FBF_ASSERT(x) if(!(x)) { return -1; }
}

#endif //FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
