//
// Created by derrick on 8/13/18.
//

#ifndef FOSBIN_FLOP_MEMMOVEIDENTIFIER_H
#define FOSBIN_FLOP_MEMMOVEIDENTIFIER_H

#include <identifiers/functionIdentifier.h>
#include <identifiers/identifierRegistrar.h>

namespace fbf {
    class MemmoveIdentifier : public FunctionIdentifier {
    public:
        explicit MemmoveIdentifier(uintptr_t location);
        explicit MemmoveIdentifier();
        ~MemmoveIdentifier() override;

        int evaluate() override;
        void setup() override;
        const std::string& getName();

        const static int OFFSET;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<MemmoveIdentifier> registrar_memmove("memmove");
}


#endif //FOSBIN_FLOP_MEMMOVEIDENTIFIER_H
