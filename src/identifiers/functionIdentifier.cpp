//
// Created by derrick on 7/6/18.
//

#include <functionIdentifier.h>

fbf::FunctionIdentifier::FunctionIdentifier(uintptr_t location) : location_(location),
                                                                  rd_(),
                                                                  mt_(rd_()),
                                                                  dist_(std::numeric_limits<int>::min(),
                                                                        std::numeric_limits<int>::max()) {

}

fbf::FunctionIdentifier::~FunctionIdentifier() {

}

uintptr_t fbf::FunctionIdentifier::get_location() {
    return location_;
}

void fbf::FunctionIdentifier::setup() {
    return;
}

int fbf::FunctionIdentifier::rand() {
    return dist_(mt_);
}

int fbf::FunctionIdentifier::run_test() {
    setup();
    return evaluate() == 0;
}
