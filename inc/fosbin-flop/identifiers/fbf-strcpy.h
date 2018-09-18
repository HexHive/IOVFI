//
// Created by derrick on 7/21/18.
//

#ifndef FOSBIN_FLOP_STRCPYIDENTIFIER_H
#define FOSBIN_FLOP_STRCPYIDENTIFIER_H

#include <fosbin-flop/identifiers/functionIdentifier.h>
#include <fosbin-flop/identifiers/identifierRegistrar.h>

namespace fbf {
    class StrcpyIdentifier : public FunctionIdentifier {
    public:
        StrcpyIdentifier(uintptr_t location);
        StrcpyIdentifier();
        virtual ~StrcpyIdentifier() override;

        virtual void evaluate() override;
        virtual void setup() override;

    protected:
        char src_[FunctionIdentifier::BUFFER_SIZE];
        char dst_[FunctionIdentifier::BUFFER_SIZE];

        StrcpyIdentifier(uintptr_t location, const std::string& subclass_name);
    };

    static IdentifierRegistrar<StrcpyIdentifier> registrar_strcpy("strcpy");
}


#endif //FOSBIN_FLOP_STRCPYIDENTIFIER_H
