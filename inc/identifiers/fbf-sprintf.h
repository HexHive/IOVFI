//
// Created by derrick on 7/21/18.
//

#ifndef FOSBIN_FLOP_SPRINTFIDENTIFIER_H
#define FOSBIN_FLOP_SPRINTFIDENTIFIER_H


#include <identifiers/functionIdentifier.h>
#include <identifiers/identifierRegistrar.h>

namespace fbf {
    class SprintfIdentifier : public FunctionIdentifier {
    public:
        explicit SprintfIdentifier(uintptr_t location);
        explicit SprintfIdentifier();
        ~SprintfIdentifier() override;

        int evaluate() override;
        void setup() override;
        const std::string& getName();

    protected:
        const char *format_ = "%d %d";
        char dst1_[FunctionIdentifier::BUFFER_SIZE];
        char dst2_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<SprintfIdentifier> registrar_sprintf("sprintf");
}


#endif //FOSBIN_FLOP_SPRINTFIDENTIFIER_H
