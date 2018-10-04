//
// Created by derrick on 7/6/18.
//

#include <identifiers/functionIdentifier.h>
#include <fosbin-flop/identifiers/functionIdentifier.h>

const int fbf::FunctionIdentifier::MAX_FAIL_RATE = 40;

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

void* fbf::FunctionIdentifier::get_value() {
    /* TODO: Implement this */
    return nullptr;
}

int fbf::FunctionIdentifier::run_test() {
    setup();
    evaluate();
    if(get_total_tests() == 0) {
        return fbf::ITestCase::FAIL;
    }

    double failRate = (double)get_failed_tests() / get_total_tests();
    int failPercent = (int)(failRate * 100);
    return (failPercent >= fbf::FunctionIdentifier::MAX_FAIL_RATE) ?
        fbf::ITestCase::FAIL : fbf::ITestCase::PASS;
}

const std::string fbf::FunctionIdentifier::get_test_name() {
    return functionName_;
}

int fbf::FunctionIdentifier::get_total_tests() {
    return totalTests_;
}

int fbf::FunctionIdentifier::get_failed_tests() {
    return failedTests_;
}
