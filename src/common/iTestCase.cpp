//
// Created by derrick on 9/18/18.
//

#include "iTestCase.h"

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
