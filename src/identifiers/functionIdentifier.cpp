//
// Created by derrick on 7/6/18.
//

#include <functionIdentifier.h>

fbf::FunctionIdentifier::FunctionIdentifier(uintptr_t location, const std::string& functionName) :
                                                                location_(location),
                                                                functionName_(functionName),
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

void fbf::FunctionIdentifier::setup() {

}

int fbf::FunctionIdentifier::rand() {
    return dist_(mt_);
}

int fbf::FunctionIdentifier::run_test() {
    setup();
    return evaluate();
}

const std::string& fbf::FunctionIdentifier::getFunctionName() {
    return functionName_;
}
