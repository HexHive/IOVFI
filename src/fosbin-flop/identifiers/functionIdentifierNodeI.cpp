//
// Created by derrick on 10/16/18.
//

#include <fosbin-flop/identifiers/functionIdentifierNodeI.h>

#include "fosbin-flop/identifiers/functionIdentifierNodeI.h"

fbf::FunctionIdentifierNodeI::FunctionIdentifierNodeI(std::string &functionName) : name_(functionName), left_(nullptr),
                                                                              right_(nullptr) {
}

fbf::FunctionIdentifierNodeI::~FunctionIdentifierNodeI() {

}

const std::string &fbf::FunctionIdentifierNodeI::get_name() const {
    return name_;
}

std::shared_ptr<fbf::FunctionIdentifierNodeI> fbf::FunctionIdentifierNodeI::register_passing(std::shared_ptr<fbf::FunctionIdentifierNodeI> func) {
    passing_funcs_.insert(func);
    return get_passing_node();
}

std::shared_ptr<fbf::FunctionIdentifierNodeI> fbf::FunctionIdentifierNodeI::register_failing(std::shared_ptr<fbf::FunctionIdentifierNodeI> func) {
    failing_funcs_.insert(func);
    return get_failing_node();
}

std::shared_ptr<fbf::FunctionIdentifierNodeI> fbf::FunctionIdentifierNodeI::get_passing_node() {
    return right_;
}

std::shared_ptr<fbf::FunctionIdentifierNodeI> fbf::FunctionIdentifierNodeI::get_failing_node() {
    return left_;
}

std::set<std::shared_ptr<fbf::FunctionIdentifierNodeI>> fbf::FunctionIdentifierNodeI::get_passing_funcs() const {
    return passing_funcs_;
}

std::set<std::shared_ptr<fbf::FunctionIdentifierNodeI>> fbf::FunctionIdentifierNodeI::get_failing_funcs() const {
    return failing_funcs_;
}

void fbf::FunctionIdentifierNodeI::set_pass_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    register_passing(node);
    right_ = node;
}

void fbf::FunctionIdentifierNodeI::set_fail_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    register_failing(node);
    left_ = node;
}

bool fbf::FunctionIdentifierNodeI::function_in_passing(std::string name) const {
    for(auto func : passing_funcs_) {
        if(name == func->get_name()) {
            return true;
        }
    }

    return false;
}

bool fbf::FunctionIdentifierNodeI::function_in_failing(std::string name) const {
    for(auto func : failing_funcs_) {
        if(name == func->get_name()) {
            return true;
        }
    }

    return false;
}

bool fbf::FunctionIdentifierNodeI::operator!=(const fbf::FunctionIdentifierNodeI &node) const {
    return (*this == node) == false;
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
        if (std::any_cast<float>(v1) == std::any_cast<float>(v2)) {
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