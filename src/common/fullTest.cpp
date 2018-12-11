//
// Created by derrick on 9/17/18.
//

#include "fullTest.h"
#include <iostream>
#include <fstream>
#include <termios.h>
#include <fullTest.h>
#include <limits>
#include <unistd.h>

namespace fs = std::experimental::filesystem;

fbf::FullTest::FullTest(fs::path descriptor, uint32_t thread_count) :
        binDesc_(descriptor),
        thread_count_(thread_count),
        pool_(thread_count),
        rand_int(std::numeric_limits<uint64_t>::min(), std::numeric_limits<uint64_t>::max()) {
    seed_rand();
}

fbf::FullTest::FullTest(fs::path descriptor, fs::path syscall_mapping, uint32_t thread_count) :
    binDesc_(descriptor, syscall_mapping),
    thread_count_(thread_count),
    pool_(thread_count),
    rand_int(std::numeric_limits<uint64_t>::min(), std::numeric_limits<uint64_t>::max()) {
    seed_rand();
}

void fbf::FullTest::seed_rand() {
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    re.seed(seed);
}

fbf::FullTest::~FullTest() {
    pool_.stop();
}

uint64_t fbf::FullTest::getRandLong() {
    return rand_int(re);
}

fbf::FullTest::FullTest(const fbf::FullTest &other):
    binDesc_(other.binDesc_), thread_count_(other.thread_count_), pool_(other.thread_count_)
{
}

fbf::FullTest &fbf::FullTest::operator=(const fbf::FullTest &other) {
    if(this != &other) {
        binDesc_ = other.binDesc_;
        thread_count_ = other.thread_count_;
        pool_.resize(thread_count_);
    }

    return *this;
}

void fbf::FullTest::run() {
    create_testcases();

    size_t test_num = 0;
    struct termios in, out, err;
    tcgetattr(0, &in);
    tcgetattr(1, &out);
    tcgetattr(2, &err);
    std::cout << "Running tests on " << binDesc_.getOffsets().size() << " offsets" << std::endl;

    for (std::vector<std::shared_ptr<fbf::TestRun>>::iterator it = testRuns_.begin();
         it != testRuns_.end(); ++it) {
        std::stringstream offset;
        offset << std::hex << (*it)->get_offset();
        tcsetattr(0, 0, &in);
        tcsetattr(1, 0, &out);
        tcsetattr(2, 0, &err);
        LOG_DEBUG << "Queueing measurement " << ++test_num
                  << " of " << testRuns_.size()
                  << " (offset 0x" << offset.str() << " - "
                  << (*it)->get_test_name()
                  << " " << binDesc_.getSym((*it)->get_offset()).name
                  << ")"
                  << " as pid " << getpid();

        std::shared_ptr<fbf::TestRun> sp = *it;
        if(thread_count_ > 1) {
            auto b = std::bind(&fbf::TestRun::run_test, sp.get());
            pool_.push(b);
        } else {
            sp->run_test();
        }
    }

    std::cout << "Waiting for all tests to complete...";
    pool_.stop(true);
    std::cout << "done!" << std::endl;
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
    if(binDesc_.isSharedLibrary()) {
        return offset;
    }

    return binDesc_.getText().location_ + offset;
}
