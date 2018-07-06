//
// Created by derrick on 7/6/18.
//

#ifndef FOSBIN_FLOP_MEMCPY_H
#define FOSBIN_FLOP_MEMCPY_H

#include <functionIdentifier.h>

namespace fbf {
    class MemcpyIdentifier : public FunctionIdentifier {
    public:
        explicit MemcpyIdentifier(uintptr_t location);

        ~MemcpyIdentifier() override;

        int evaluate() override;

        void setup() override;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
        char dst_[FunctionIdentifier::BUFFER_SIZE];
    };
}

#endif //FOSBIN_FLOP_MEMCPY_H
