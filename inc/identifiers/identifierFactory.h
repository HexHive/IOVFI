//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_IDENTIFIERFACTORY_H
#define FOSBIN_FLOP_IDENTIFIERFACTORY_H
#include <identifiers/functionIdentifier.h>
#include <string>
#include <functional>
#include <memory>
#include <map>
#include <set>

namespace fbf {
    class IdentifierFactory {
        std::map<std::string, std::function<fbf::FunctionIdentifier*(uintptr_t)>> registry_;
        IdentifierFactory();
        ~IdentifierFactory();

    public:
        void RegisterFactoryFunction(std::string name, std::function<fbf::FunctionIdentifier*(uintptr_t)> identifierFactory);
        std::shared_ptr<fbf::FunctionIdentifier> CreateIdentifier(std::string name, uintptr_t addr);
        static fbf::IdentifierFactory* Instance();
        const std::set<std::string> getRegistered();
    };
}

#endif //FOSBIN_FLOP_IDENTIFIERFACTORY_H
