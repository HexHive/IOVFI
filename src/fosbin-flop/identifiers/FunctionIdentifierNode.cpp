//
// Created by derrick on 11/5/18.
//

#include "fosbin-flop/identifiers/FunctionIdentifierNode.h"

fbf::FunctionIdentifierNode::FunctionIdentifierNode(const char *functionName) : FunctionIdentifierNodeI(functionName) {

}

bool fbf::FunctionIdentifierNode::test(uintptr_t location) {
    return !get_name().empty();
}

void fbf::FunctionIdentifierNode::set_pass_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    return;
}

void fbf::FunctionIdentifierNode::set_fail_node(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    return;
}
