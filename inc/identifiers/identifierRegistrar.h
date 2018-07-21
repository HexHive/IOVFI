//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_IDENTIFIERREGISTRAR_H
#define FOSBIN_FLOP_IDENTIFIERREGISTRAR_H

#include <identifiers/functionIdentifier.h>
#include <identifiers/identifierFactory.h>
#include <string>

namespace fbf {
    template<class T>
    class IdentifierRegistrar {
    public:
        IdentifierRegistrar(std::string name) {
            fbf::IdentifierFactory::
            Instance()->RegisterFactoryFunction(name,
                                                [](uintptr_t addr) -> fbf::FunctionIdentifier * {
                                                    return new T(addr);
                                                });
        };
    };
}


#endif //FOSBIN_FLOP_IDENTIFIERREGISTRAR_H
