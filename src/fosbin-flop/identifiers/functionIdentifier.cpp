//
// Created by derrick on 7/6/18.
//

#include <identifiers/functionIdentifier.h>

fbf::FunctionIdentifier::FunctionIdentifier(uintptr_t location, const std::string &functionName) :
        ITestCase(),
        location_(location),
        functionName_(functionName) {

}

fbf::FunctionIdentifier::FunctionIdentifier() :
        ITestCase(),
        location_(0),
        functionName_("") {}

fbf::FunctionIdentifier::~FunctionIdentifier() = default;

uintptr_t fbf::FunctionIdentifier::get_location() {
    return location_;
}

void fbf::FunctionIdentifier::setup() {

}

int fbf::FunctionIdentifier::run_test() {
    setup();
    return evaluate();
}

const std::string fbf::FunctionIdentifier::get_test_name() {
    return functionName_;
}
