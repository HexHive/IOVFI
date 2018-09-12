//
// Created by derrick on 7/6/18.
//

#include <identifiers/functionIdentifier.h>

fbf::FunctionIdentifier::FunctionIdentifier(uintptr_t location, const std::string& functionName) :
                                                                location_(location),
                                                                functionName_(functionName), totalTests_(0),
                                                                failedTests_(0), {

}

fbf::FunctionIdentifier::FunctionIdentifier() : location_(0),
                                                functionName_(""), totalTests_(0), failedTests_(0),{}

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

const std::string& fbf::FunctionIdentifier::getFunctionName() {
    return functionName_;
}

int fbf::FunctionIdentifier::get_total_tests() { return totalTests_; }

int fbf::FunctionIdentifier::get_failed_tests() { return failedTests_; }
