//
//// Created by derrick on 10/16/18.
////
//
//#include <fosbin-flop/testNode.h>
//
//fbf::TestNode::TestNode(std::any retValue, std::initializer_list<std::any> args) {
//    args_ = std::make_tuple(args);
//    argCount_ = args.size();
//    retVal_ = retValue;
//}
//
//fbf::TestNode::TestNode(const fbf::TestNode &other) {
//    argCount_ = other.argCount_;
//    args_ = other.args_;
//    retVal_ = other.retVal_;
//    left_ = other.left_;
//    right_ = other.right_;
//}
//
//bool fbf::TestNode::test(uintptr_t location) {
//
//}
//
//fbf::arg_count_t fbf::TestNode::getArgCount() {
//    return argCount_;
//}
//
//std::any fbf::TestNode::get_return_val() {
//    return retVal_;
//}
//
//std::shared_ptr<fbf::TestNode> fbf::TestNode::get_pass_node() {
//    return right_;
//}
//
//std::shared_ptr<fbf::TestNode> fbf::TestNode::get_fail_node() {
//    return left_;
//}
