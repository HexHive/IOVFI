//
// Created by derrick on 10/16/18.
//

#include <fosbin-flop/identifierNodeTestCase.h>

#include "../../../inc/fosbin-flop/identifierNodeTestCase.h"

fbf::IdentifierNodeTestCase::IdentifierNodeTestCase(std::shared_ptr<fbf::FunctionIdentifierNodeI> root,
                                                    uintptr_t location)
        : ITestCase(), location_(location), root_(root), leaf_(nullptr) {

}

const std::string fbf::IdentifierNodeTestCase::get_test_name() {
    std::stringstream ss;
    ss << "0x" << std::hex << location_;
    return ss.str();
}

int fbf::IdentifierNodeTestCase::run_test() {
    std::shared_ptr<fbf::FunctionIdentifierNodeI> curr = root_;
    std::shared_ptr<fbf::FunctionIdentifierNodeI> prev = curr;
    bool prev_result = false;
    while (curr != nullptr) {
        prev = curr;
        prev_result = curr->test(location_);
        if (!prev_result) {
            curr = curr->get_failing_node();
        } else {
            curr = curr->get_passing_node();
        }
    }

    /* We have made it to a leaf. Either the last result was
     * true, in which case, we can identify the function, or
     * false and the function is unknown
     */
    leaf_ = prev;
}

void fbf::IdentifierNodeTestCase::output_result(std::ostream &out) {
    if(leaf_) {
        out << leaf_->get_name();
    } else {
        out << "UNKNOWN";
    }
}

uint64_t fbf::IdentifierNodeTestCase::get_value() {
    return 0;
}

uintptr_t fbf::IdentifierNodeTestCase::get_location() {
    return location_;
}