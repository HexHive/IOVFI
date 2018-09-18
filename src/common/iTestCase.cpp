//
// Created by derrick on 9/18/18.
//

#include "iTestCase.h"

fbf::ITestCase::ITestCase() :
        rd_(),
        mt_(rd_()),
        dist_(std::numeric_limits<int>::min(),
              std::numeric_limits<int>::max())
{

}

int fbf::ITestCase::rand() {
    return dist_(mt_);
}
