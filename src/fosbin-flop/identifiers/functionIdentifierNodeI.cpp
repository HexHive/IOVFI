//
// Created by derrick on 10/16/18.
//

#include "fosbin-flop/identifiers/functionIdentifierNodeI.h"
#include "iTestCase.h"
#include <signal.h>

fbf::FunctionIdentifierNodeI::FunctionIdentifierNodeI(std::string &functionName) : name_(functionName), left_(nullptr),
                                                                              right_(nullptr) {
}

fbf::FunctionIdentifierNodeI::FunctionIdentifierNodeI(const char* functionName) : name_(functionName), left_(nullptr),
                                                                                   right_(nullptr) {
}

fbf::FunctionIdentifierNodeI::~FunctionIdentifierNodeI() {

}

const std::string &fbf::FunctionIdentifierNodeI::get_name() const {
    return name_;
}

std::shared_ptr<fbf::FunctionIdentifierNodeI> fbf::FunctionIdentifierNodeI::get_passing_node() {
    return right_;
}

std::shared_ptr<fbf::FunctionIdentifierNodeI> fbf::FunctionIdentifierNodeI::get_failing_node() {
    return left_;
}

void fbf::FunctionIdentifierNodeI::set_pass_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    right_ = node;
}

void fbf::FunctionIdentifierNodeI::set_fail_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    left_ = node;
}

bool fbf::FunctionIdentifierNodeI::compare_any(const std::any v1, const std::any v2) {
    try {
        if (std::any_cast<int>(v1) == std::any_cast<int>(v2)) {
            return true;
        } else {
            return false;
        }
    } catch (const std::bad_any_cast &e) {}

    try {
        if (std::any_cast<double>(v1) == std::any_cast<double>(v2)) {
            return true;
        } else {
            return false;
        }
    } catch (const std::bad_any_cast &e) {}

    try {
        if (std::any_cast<void *>(v1) == std::any_cast<void *>(v2)) {
            return true;
        } else {
            return false;
        }
    } catch (const std::bad_any_cast &e) {}

    return false;
}