//
// Created by derrick on 7/21/18.
//

#ifndef FOSBIN_FLOP_STRCPYIDENTIFIER_H
#define FOSBIN_FLOP_STRCPYIDENTIFIER_H

#include <identifiers/functionIdentifier.h>
#include <identifiers/identifierRegistrar.h>

namespace fbf {
    class StrcpyIdentifier : public FunctionIdentifier {
    public:
        explicit StrcpyIdentifier(uintptr_t location);
        explicit StrcpyIdentifier();
        ~StrcpyIdentifier() override;

        int evaluate() override;
        void setup() override;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
        char dst_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<StrcpyIdentifier> registrar("strcpy");
}


#endif //FOSBIN_FLOP_STRCPYIDENTIFIER_H
