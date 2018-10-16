//
// Created by derrick on 7/8/18.
//

#include "fosbin-flop/fullIdentifierTest.h"
#include <fstream>
#include <set>
#include <algorithm>
#include <experimental/filesystem>
#include <identifiers/identifierFactory.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>
#include <termios.h>

namespace fs = std::experimental::filesystem;

fbf::FullIdentifierTest::FullIdentifierTest(fs::path descriptor, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    create_testcases();
}

fbf::FullIdentifierTest::~FullIdentifierTest() = default;

void fbf::FullIdentifierTest::create_testcases() {
    std::string name = "sin";
    std::shared_ptr<fbf::FunctionIdentifierNode<double, double>> sinNode0 = std::make_shared<fbf::FunctionIdentifierNode<double, double>>(
            name, 0.0, 0.0);
    insertFunctionIdentifier(sinNode0);

    name = "cos";
    std::shared_ptr<fbf::FunctionIdentifierNode<double, double>> cosNode0 = std::make_shared<fbf::FunctionIdentifierNode<double, double>>(
            name, 1.0, 0.0);
    insertFunctionIdentifier(cosNode0);

    name = "tan";
    std::shared_ptr<fbf::FunctionIdentifierNode<double, double>> tanNode0 = std::make_shared<fbf::FunctionIdentifierNode<double, double>>(
            name, 0.0, 0.0);
    insertFunctionIdentifier(tanNode0);
    std::shared_ptr<fbf::FunctionIdentifierNode<double, double>> tanNode1 = std::make_shared<fbf::FunctionIdentifierNode<double, double>>(
            name, 1.0, 1.570796327);
    insertFunctionIdentifier(tanNode1);


}

void fbf::FullIdentifierTest::insertFunctionIdentifier(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    if (testGraphs_.find(node->get_arg_count()) == testGraphs_.end()) {
        testGraphs_.emplace(std::make_pair(node->get_arg_count(), node));
        return;
    }

    std::shared_ptr<fbf::FunctionIdentifierNodeI> curr = testGraphs_[node->get_arg_count()];
    std::shared_ptr<fbf::FunctionIdentifierNodeI> prev = curr;
    while (curr != nullptr) {
        prev = curr;
        if (*curr == *node) {
            curr = curr->get_pass_node();
        } else {
            curr = curr->get_fail_node();
        }
    }

    if (*prev == *node) {
        prev->set_pass_node(node);
    } else {
        prev->set_fail_node(node);
    }
}
