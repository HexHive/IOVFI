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

fbf::FullIdentifierTest::FullIdentifierTest(fs::path descriptor, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    create_testcases();
}

fbf::FullIdentifierTest::~FullIdentifierTest() {
    for(void* buffer : buffers_) {
        free(buffer);
    }
};

void fbf::FullIdentifierTest::create_testcases() {
#include "Identifiers.inc"
    for(uintptr_t location : binDesc_.getOffsets()) {
        std::shared_ptr<fbf::IdentifierNodeTestCase> test = std::make_shared<fbf::IdentifierNodeTestCase>(root,
                location);
        testRuns_.push_back(std::make_shared<fbf::TestRun>(test, test->get_location()));
    }
}
