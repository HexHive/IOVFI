//
// Created by derrick on 9/17/18.
//

#include "fullTest.h"
#include <iostream>
#include <fstream>
#include <termios.h>
#include <fullTest.h>


namespace fs = std::experimental::filesystem;

fbf::FullTest::FullTest(fs::path descriptor, uint32_t thread_count) :
        binDesc_(descriptor), pool_(thread_count) {}

fbf::FullTest::~FullTest() {
    pool_.stop();
}

fbf::FullTest::FullTest(const fbf::FullTest &other):
    binDesc_(other.binDesc_), pool_(other.pool_.size())
{
}

fbf::FullTest &fbf::FullTest::operator=(const fbf::FullTest &other) {
    if(this != &other) {
        binDesc_ = other.binDesc_;
        pool_.resize(other.pool_.size());
    }

    return *this;
}

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
        std::cout << "Queueing measurement " << ++test_num
                  << " of " << testRuns_.size()
                  << " (offset 0x" << offset.str() << " - "
                  << (*it)->get_test_name()
                  << ")" << std::endl;

        std::shared_ptr<fbf::TestRun> sp = *it;
        auto b = std::bind(&fbf::TestRun::run_test, sp.get());
        pool_.push(b);
    }

    pool_.stop(true);
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