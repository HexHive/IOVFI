//
// Created by derrick on 8/13/18.
//

#include "identifiers/fbf-memmove.h"

fbf::MemmoveIdentifier::MemmoveIdentifier(uintptr_t location) :
    FunctionIdentifier(location, getName()) {}

fbf::MemmoveIdentifier::MemmoveIdentifier() : FunctionIdentifier();

fbf::MemmoveIdentifier::~MemmoveIdentifier() = default;

int fbf::MemmoveIdentifier::evaluate() {
    return 0;
}

void fbf::MemmoveIdentifier::setup() {
    
}

const std::string &fbf::MemmoveIdentifier::getName() {
    static const std::string name = "memmove";
    return name;
}
