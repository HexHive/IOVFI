//
// Created by derrick on 10/15/18.
//

#include <fosbin-flop/testNode.h>
#include <functional>

const uint8_t fbf::TestNode::MAX_ARGS = 6;

fbf::TestNode::TestNode(std::vector<std::any> args, std::any returnValue)
    : args_(args), retVal_(returnValue)
{
    if(args_.size() > MAX_ARGS) {
        throw std::runtime_error("Too many arguments");
    }
}

bool fbf::TestNode::test(uintptr_t location) {
    using namespace std::placeholders;

    std::function<

    switch(args_.size()) {
        case MAX_ARGS:
            auto r = std::bind(location, _1, _2, _3, _4, _5, _6)
                    (args_[0], args_[1], args_[2], args_[3], args_[4], args_[5]);
            return
    }
}

std::vector<std::any> &fbf::TestNode::getArgs() {
    return args_;
}

std::any &fbf::TestNode::getReturnValue() {
    return retVal_;
}
