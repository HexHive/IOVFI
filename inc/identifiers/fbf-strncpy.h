//
// Created by derrick on 8/13/18.
//

#ifndef FOSBIN_FLOP_STRNCPYIDENTIFIER_H
#define FOSBIN_FLOP_STRNCPYIDENTIFIER_H

#include <identifiers/fbf-strcpy.h>

namespace fbf {
    class StrncpyIdentifier : public StrcpyIdentifier {
    public:
        StrncpyIdentifier(uintptr_t location);
        StrncpyIdentifier();

        int evaluate() override;

        const static size_t BYTES_COPIED;
    };

    static IdentifierRegistrar<StrncpyIdentifier> registrar_strncpy("strncpy");
}


#endif //FOSBIN_FLOP_STRNCPYIDENTIFIER_H
