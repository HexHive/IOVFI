//
// Created by derrick on 7/8/18.
//

#include <fstream>
#include <set>
#include <algorithm>
#include <experimental/filesystem>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <termios.h>
#include <identifierNodeTestCase.h>
#include <fosbin-flop/fullIdentifierTest.h>
#include <fosbin-flop/identifiers/FunctionIdentifierNode.h>

namespace fs = std::experimental::filesystem;

fbf::FullIdentifierTest::FullIdentifierTest(fs::path descriptor, fs::path arg_counts, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    create_testcases();
}

fbf::FullIdentifierTest::~FullIdentifierTest() {
    for(void* buffer : buffers_) {
        free(buffer);
    }
};

void fbf::FullIdentifierTest::create_testcases() {
    std::shared_ptr<fbf::FunctionIdentifierInternalNode<double, double>> node0 = std::make_shared<fbf::FunctionIdentifierInternalNode<double, double>>(0.46800071937081683, -0.7592854459485416);
    std::shared_ptr<fbf::FunctionIdentifierNode> strcmp_ = std::make_shared<fbf::FunctionIdentifierNode>("strcmp");
    std::shared_ptr<fbf::FunctionIdentifierNode> exp_ = std::make_shared<fbf::FunctionIdentifierNode>("exp");
    node0->set_pass_node(exp_);
    node0->set_fail_node(strcmp_);
}
