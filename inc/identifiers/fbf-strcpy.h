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
        StrcpyIdentifier(uintptr_t location);
        StrcpyIdentifier();
        virtual ~StrcpyIdentifier() override;

        virtual int evaluate() override;
        virtual void setup() override;
        virtual const std::string& getName();

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
        char dst_[FunctionIdentifier::BUFFER_SIZE];
    };

    static IdentifierRegistrar<StrcpyIdentifier> registrar_strcpy("strcpy");
}


#endif //FOSBIN_FLOP_STRCPYIDENTIFIER_H
