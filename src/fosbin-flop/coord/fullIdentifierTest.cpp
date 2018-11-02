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

namespace fs = std::experimental::filesystem;

fbf::FullIdentifierTest::FullIdentifierTest(fs::path descriptor, fs::path arg_counts, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    create_testcases();
}

fbf::FullIdentifierTest::~FullIdentifierTest() = default;

void fbf::FullIdentifierTest::create_testcases() {

}
