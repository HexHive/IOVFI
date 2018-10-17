//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_FULLTEST_H
#define FOSBIN_FLOP_FULLTEST_H

#include <fosbin-flop.h>
#include "fullTest.h"
#include <fosbin-flop/functionIdentifierNodeGraphVisitor.h>

namespace fs = std::experimental::filesystem;

namespace fbf {
    class FullIdentifierTest : public FullTest {
    public:
        FullIdentifierTest(fs::path descriptor, fs::path arg_counts, uint32_t thread_count = 1);

        virtual ~FullIdentifierTest();

    protected:
        virtual void create_testcases();

        virtual void parse_arg_counts(fs::path arg_counts);

        std::map<arg_count_t, std::shared_ptr<fbf::FunctionIdentifierNodeI>> testGraphs_;
        std::map<arg_count_t, std::set<uintptr_t>> locations_;

        virtual void insertFunctionIdentifier(std::shared_ptr<fbf::FunctionIdentifierNodeI> node);
    };
}

#endif //FOSBIN_FLOP_FULLTEST_H
