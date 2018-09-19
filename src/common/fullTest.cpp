//
// Created by derrick on 9/17/18.
//

#include "fullTest.h"
#include <iostream>
#include <fstream>
#include <termios.h>

namespace fs = std::experimental::filesystem;

fbf::FullTest::FullTest(fs::path descriptor) :
        binDesc_(descriptor) { }

fbf::FullTest::~FullTest() { }

void fbf::FullTest::run() {
    size_t test_num = 0;
    struct termios in, out, err;
    tcgetattr(0, &in);
    tcgetattr(1, &out);
    tcgetattr(2, &err);

    for (std::vector<std::shared_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        std::stringstream offset;
        offset << std::hex << (*it)->get_offset();
        tcsetattr(0, 0, &in);
        tcsetattr(1, 0, &out);
        tcsetattr(2, 0, &err);
        std::cout << "Running measurement " << ++test_num
                  << " (offset 0x" << offset.str() << " - "
                  << (*it)->get_test_name()
                  << ") of "
                  << testRuns_.size() << std::endl;
        (*it)->run_test();
    }
}

void fbf::FullTest::output(std::ostream &out) {
    size_t i = 0;
    size_t total = testRuns_.size();
    for (; i < total; i++) {
        out << "Outputting " << i + 1 << " of " << total << std::endl;
        testRuns_[i]->output_results(out);
    }
}

uintptr_t fbf::FullTest::compute_location(uintptr_t offset) {
    return binDesc_.getText().location_ + offset;
}