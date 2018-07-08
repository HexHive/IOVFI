//
// Created by derrick on 7/8/18.
//

#include <string>
#include <functionIdentifier.h>
#include <functional>
#include <memory>
#include <identifierFactory.h>

fbf::IdentifierFactory::IdentifierFactory() {

}

fbf::IdentifierFactory::~IdentifierFactory() = default;

void fbf::IdentifierFactory::RegisterFactoryFunction(std::string name, std::function<fbf::FunctionIdentifier *(uintptr_t)> identifierFactory) {
    registry_[name] = identifierFactory;
}

std::shared_ptr<fbf::FunctionIdentifier> fbf::IdentifierFactory::CreateIdentifier(std::string name, uintptr_t addr) {
    auto factory = nullptr;
    auto it = registry_.find(name);
    if(it != registry_.end()) {
        return std::shared_ptr<fbf::FunctionIdentifier>(it->second(addr));
    }

    return nullptr;
}

fbf::IdentifierFactory *fbf::IdentifierFactory::Instance() {
    static fbf::IdentifierFactory factory;
    return &factory;
}
