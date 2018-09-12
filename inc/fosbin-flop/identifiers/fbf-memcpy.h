//
// Created by derrick on 7/6/18.
//

#ifndef FOSBIN_FLOP_MEMCPY_H
#define FOSBIN_FLOP_MEMCPY_H

#include <fosbin-flop/identifiers/functionIdentifier.h>
#include <fosbin-flop/identifiers/identifierRegistrar.h>

namespace fbf {
    class MemcpyIdentifier : public FunctionIdentifier {
    public:
        explicit MemcpyIdentifier(uintptr_t location);
        explicit MemcpyIdentifier();
        ~MemcpyIdentifier() override;

        void evaluate() override;
        void setup() override;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
        char dst_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<MemcpyIdentifier> registrar_memcpy("memcpy");
}

#endif //FOSBIN_FLOP_MEMCPY_H
