//
// Created by derrick on 10/16/18.
//

#include <fosbin-flop/identifierNodeTestCase.h>

#include "../../../inc/fosbin-flop/identifierNodeTestCase.h"

fbf::IdentifierNodeTestCase::IdentifierNodeTestCase(std::shared_ptr<fbf::FunctionIdentifierNodeI> root,
                                                    uintptr_t location) : ITestCase(), location_(location), root_(root){

}

const std::string fbf::IdentifierNodeTestCase::get_test_name() {
    std::stringstream ss;
    ss << "0x" << std::hex << location_ << std::endl;
    return ss.str();
}

int fbf::IdentifierNodeTestCase::run_test() {
    std::shared_ptr<fbf::FunctionIdentifierNodeI> curr = root_;
    std::shared_ptr<fbf::FunctionIdentifierNodeI> prev = curr;
    bool prev_result = false;
    while(curr != nullptr) {
        prev = curr;
        prev_result = curr->test(location_);
        if(!prev_result) {
            curr = curr->get_fail_node();
        } else {
            curr = curr->get_pass_node();
        }
    }

    if(prev_result) {
        ided_function_ = prev->get_name();
        return PASS;
    } else {
        return FAIL;
    }
}

uint64_t fbf::IdentifierNodeTestCase::get_value() {
    return 0;
}

uintptr_t fbf::IdentifierNodeTestCase::get_location() {
    return location_;
}
