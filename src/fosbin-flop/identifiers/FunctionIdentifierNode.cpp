//
// Created by derrick on 11/5/18.
//

#include "fosbin-flop/identifiers/FunctionIdentifierNode.h"

fbf::FunctionIdentifierNode::FunctionIdentifierNode(const char *functionName,
                                                    std::shared_ptr<FunctionIdentifierNodeI> confirmation) :
        FunctionIdentifierNodeI(functionName), confirmation_(confirmation) {

}

bool fbf::FunctionIdentifierNode::test(uintptr_t location) {
    return confirmation_->test(location);
}

bool fbf::FunctionIdentifierNode::test_arity(uintptr_t location, arg_count_t arity) {
    return confirmation_->test_arity(location, arity);
}

fbf::arg_count_t fbf::FunctionIdentifierNode::get_arg_count() {
    return confirmation_->get_arg_count();
}

void fbf::FunctionIdentifierNode::set_fail_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    return;
}

void fbf::FunctionIdentifierNode::set_pass_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    return;
}