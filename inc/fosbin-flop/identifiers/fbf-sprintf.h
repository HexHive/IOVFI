//
// Created by derrick on 7/21/18.
//

#ifndef FOSBIN_FLOP_SPRINTFIDENTIFIER_H
#define FOSBIN_FLOP_SPRINTFIDENTIFIER_H


#include <fosbin-flop/identifiers/functionIdentifier.h>
#include <fosbin-flop/identifiers/identifierRegistrar.h>

namespace fbf {
    class SprintfIdentifier : public FunctionIdentifier {
    public:
        explicit SprintfIdentifier(uintptr_t location);
        explicit SprintfIdentifier();
        ~SprintfIdentifier() override;

        void evaluate() override;
        void setup() override;

    protected:
        const char *format_ = "%d %d";
        char dst1_[FunctionIdentifier::BUFFER_SIZE];
        char dst2_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<SprintfIdentifier> registrar_sprintf("sprintf");
}


#endif //FOSBIN_FLOP_SPRINTFIDENTIFIER_H
