//
// Created by derrick on 9/18/18.
//

#include <iTestCase.h>

#include "iTestCase.h"

const size_t fbf::ITestCase::POINTER_SIZE = 512;

fbf::ITestCase::ITestCase() :
        re_(),
        dist_(std::numeric_limits<int>::min(),
              std::numeric_limits<int>::max()) {
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    re_.seed(seed);
}

int fbf::ITestCase::rand() {
    return dist_(re_);
}

void fbf::ITestCase::output_result(std::ostream &out) {
    return;
}

void fbf::ITestCase::input_result(std::istream &in) {
    return;
}

pid_t fbf::ITestCase::test_fork() {
    std::cout << std::flush;
    pid_t child = fork();
    if(child < 0) {
        throw std::runtime_error("Could not fork child test");
    }
    return child;
}

uintptr_t fbf::ITestCase::get_location() {
    return location_;
}

void fbf::ITestCase::set_location(uintptr_t location) {
    location_ = location;
}
