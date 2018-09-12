//
// Created by derrick on 7/6/18.
//

#include <identifiers/functionIdentifier.h>

fbf::FunctionIdentifier::FunctionIdentifier(uintptr_t location, const std::string &functionName) :
        location_(location),
        functionName_(functionName),
        totalTests_(0), failedTests_(0),
        rd_(),
        mt_(rd_()),
        dist_(std::numeric_limits<int>::min(),
              std::numeric_limits<int>::max()) {

}

fbf::FunctionIdentifier::FunctionIdentifier() : location_(0),
                                                functionName_(""),
                                                rd_(),
                                                mt_(rd_()),
                                                dist_(std::numeric_limits<int>::min(),
                                                      std::numeric_limits<int>::max()) {}

fbf::FunctionIdentifier::~FunctionIdentifier() = default;

uintptr_t fbf::FunctionIdentifier::get_location() {
    return location_;
}

void fbf::FunctionIdentifier::setup() { }

int fbf::FunctionIdentifier::rand() {
    return dist_(mt_);
}

int fbf::FunctionIdentifier::run_test() {
    setup();
    evaluate();
    if(get_total_tests() == 0) {
        return 0;
    }
    double failRate = (double)get_failed_tests() / get_total_tests();
    return (int)(failRate * 100);
}

const std::string &fbf::FunctionIdentifier::get_function_name() {
    return functionName_;
}

int fbf::FunctionIdentifier::get_total_tests() { return totalTests_; }

int fbf::FunctionIdentifier::get_failed_tests() { return failedTests_; }
