//
// Created by derrick on 10/16/18.
//

#include <fosbin-flop/identifierNodeTestCase.h>

fbf::IdentifierNodeTestCase::IdentifierNodeTestCase(std::shared_ptr<fbf::FunctionIdentifierNodeI> root,
                                                    uintptr_t location, uint32_t arity)
        : ITestCase(), root_(root), leaf_(nullptr), arity_(arity) {
    set_location(location);
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
        prev_result = curr->test_arity(location_, arity_);
        if (!prev_result) {
            LOG_DEBUG << std::hex << location_ << std::dec << " failed";
            curr = curr->get_failing_node();
        } else {
            LOG_DEBUG << std::hex << location_ << std::dec << " succeeded";
            curr = curr->get_passing_node();
        }
    }

    /* We have made it to a leaf. Either the last result was
     * true, in which case, we can identify the function, or
     * false and the function is unknown
     */
    LOG_DEBUG << std::hex << location_ << std::dec << " is at leaf " << prev->get_name();
    if(prev_result) {
        leaf_ = prev;
        LOG_INFO << "FOUND 0x" << std::hex << location_ << std::dec << " to be " << leaf_->get_name() << std::endl;
        return fbf::ITestCase::PASS;
    } else {
        LOG_DEBUG << "Leaf at " << std::hex << location_ << " unconfirmed";
        return fbf::ITestCase::FAIL;
    }
}

void fbf::IdentifierNodeTestCase::output_result(std::ostream &out) {
    if(leaf_) {
        out << leaf_->get_name();
    } else {
        out << "UNKNOWN";
    }
}