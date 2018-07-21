//
// Created by derrick on 7/6/18.
//

#ifndef FOSBIN_FLOP_MEMCPY_H
#define FOSBIN_FLOP_MEMCPY_H

#include <identifiers/functionIdentifier.h>
#include <identifiers/identifierRegistrar.h>

namespace fbf {
    class MemcpyIdentifier : public FunctionIdentifier {
    public:
        explicit MemcpyIdentifier(uintptr_t location);
        explicit MemcpyIdentifier();
        ~MemcpyIdentifier() override;

        int evaluate() override;
        void setup() override;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
        char dst_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<MemcpyIdentifier> registrar("memcpy");
}

#endif //FOSBIN_FLOP_MEMCPY_H
