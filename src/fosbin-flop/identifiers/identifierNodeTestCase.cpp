//
// Created by derrick on 10/16/18.
//

#include <fosbin-flop/identifierNodeTestCase.h>

#include "../../../inc/fosbin-flop/identifierNodeTestCase.h"

fbf::IdentifierNodeTestCase::IdentifierNodeTestCase(std::shared_ptr<fbf::FunctionIdentifierNodeI> root,
                                                    uintptr_t location)
        : ITestCase(), location_(location), root_(root) {

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

    std::set<std::shared_ptr<fbf::FunctionIdentifierNodeI>> identified_funcs;

    if (prev_result) {
        identified_funcs = prev->get_passing_funcs();
    } else {
        identified_funcs = prev->get_failing_funcs();
    }

    if (identified_funcs.empty()) {
        return FAIL;
    }

    for (auto func : identified_funcs) {
        ided_functions_.insert(func->get_name());
    }

    /* TODO: Report back the results in a better way */
    std::cout << "0x" << std::hex << location_ << ": ";
    output_result(std::cout);
    std::cout << std::endl;

    return PASS;
}

void fbf::IdentifierNodeTestCase::output_result(std::ostream &out) {
    for (std::string name : ided_functions_) {
        out << name << " ";
    }
}

uint64_t fbf::IdentifierNodeTestCase::get_value() {
    return 0;
}

uintptr_t fbf::IdentifierNodeTestCase::get_location() {
    return location_;
}


