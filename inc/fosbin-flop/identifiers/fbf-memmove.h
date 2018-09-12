//
// Created by derrick on 8/13/18.
//

#ifndef FOSBIN_FLOP_MEMMOVEIDENTIFIER_H
#define FOSBIN_FLOP_MEMMOVEIDENTIFIER_H

#include <fosbin-flop/identifiers/functionIdentifier.h>
#include <fosbin-flop/identifiers/identifierRegistrar.h>

namespace fbf {
    class MemmoveIdentifier : public FunctionIdentifier {
    public:
        explicit MemmoveIdentifier(uintptr_t location);
        explicit MemmoveIdentifier();
        ~MemmoveIdentifier() override;

        void evaluate() override;
        void setup() override;

        const static int OFFSET;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<MemmoveIdentifier> registrar_memmove("memmove");
}


#endif //FOSBIN_FLOP_MEMMOVEIDENTIFIER_H
