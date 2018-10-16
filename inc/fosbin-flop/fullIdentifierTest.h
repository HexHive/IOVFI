//
// Created by derrick on 7/8/18.
//

#ifndef FOSBIN_FLOP_FULLTEST_H
#define FOSBIN_FLOP_FULLTEST_H

#include <experimental/filesystem>
#include <testRun.h>
#include <iostream>
#include "binaryDescriptor.h"
#include "fullTest.h"
#include <boost/graph/adjacency_list.hpp>
#include "fosbin-flop/testNode.h"

namespace fs = std::experimental::filesystem;

namespace fbf {
    class FullIdentifierTest : public FullTest {
    public:
        FullIdentifierTest(fs::path descriptor, uint32_t thread_count = 1);
        virtual ~FullIdentifierTest();
    protected:
        virtual void create_testcases();
    };
}

#endif //FOSBIN_FLOP_FULLTEST_H
