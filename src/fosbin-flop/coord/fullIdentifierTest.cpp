//
// Created by derrick on 7/8/18.
//

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
#include <identifierNodeTestCase.h>
#include <fosbin-flop/fullIdentifierTest.h>

namespace fs = std::experimental::filesystem;

fbf::FullIdentifierTest::FullIdentifierTest(fs::path descriptor, fs::path arg_counts, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    parse_arg_counts(arg_counts);
    create_testcases();
}

fbf::FullIdentifierTest::~FullIdentifierTest() = default;

void fbf::FullIdentifierTest::parse_arg_counts(fs::path arg_counts) {
    std::fstream argCountFile(arg_counts);
    std::string line;
    size_t linenum = 0;
    while (std::getline(argCountFile, line)) {
        linenum++;
        if (line.empty() || line[0] == '#') {
            continue;
        }

        size_t index = line.find('=');
        if (index == std::string::npos) {
            std::stringstream msg;
            msg << "Invalid line at line " << linenum;
            msg << ": " << line;
            LOG_ERR << msg.str();
            throw std::runtime_error(msg.str());
        }
        std::string sym = line.substr(0, index);
        arg_count_t arg_count;
        std::stringstream sarg_count;
        sarg_count << line.substr(index + 1);
        sarg_count >> arg_count;

        uintptr_t addr = binDesc_.getSymLocation(sym);
        if (addr == (uintptr_t) -1) {
            LOG_ERR << "Could not find symbol " << sym;
            continue;
        }

        locations_[arg_count].insert(addr);
    }
}

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
            name, 1.0, 0.78539816339000000);
    insertFunctionIdentifier(tanNode1);
}

void fbf::FullIdentifierTest::insertFunctionIdentifier(std::shared_ptr<fbf::FunctionIdentifierNodeI> node) {
    node->register_passing(node);

    if (testGraphs_.find(node->get_arg_count()) == testGraphs_.end()) {
        testGraphs_.emplace(std::make_pair(node->get_arg_count(), node));

        for (uintptr_t addr : locations_[node->get_arg_count()]) {
            std::shared_ptr<fbf::IdentifierNodeTestCase> testCase = std::make_shared<fbf::IdentifierNodeTestCase>(
                    node,
                    addr);
            std::shared_ptr<fbf::TestRun> testRun = std::make_shared<fbf::TestRun>(testCase, addr);
            testRuns_.push_back(testRun);
        }

        return;
    }
    std::shared_ptr<fbf::FunctionIdentifierNodeI> curr = testGraphs_[node->get_arg_count()];
    std::shared_ptr<fbf::FunctionIdentifierNodeI> prev = curr;
    while(curr != nullptr) {
        prev = curr;
        if(*node == *curr || curr->function_in_passing(node->get_name())) {
            curr->register_passing(node);
            curr = curr->get_passing_node();
        } else {
            curr->register_failing(node);
            curr = curr->get_failing_node();
        }
    }

    if(*prev != *node && prev->function_in_failing(node->get_name())) {
        prev->set_fail_node(node);
    } else if(*prev != *node && prev->function_in_passing(node->get_name())) {
        prev->set_pass_node(node);
    }
}
