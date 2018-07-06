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
        FunctionIdentifier(uintptr_t location);

        virtual ~FunctionIdentifier(void);

        virtual int run_test(void);

        uintptr_t get_location(void);

        const static size_t BUFFER_SIZE = 32;

    protected:
        uintptr_t location_;

        int rand(void);

        virtual int evaluate(void) = 0;

        virtual void setup(void);

    private:
        std::random_device rd_;
        std::mt19937 mt_;
        std::uniform_int_distribution<int> dist_;
    };

#define FBF_ASSERT(x) if(!(x)) { return -1; }
}

#endif //FOSBIN_FLOP_FUNCTIONIDENTIFIER_H
