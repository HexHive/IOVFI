//
// Created by derrick on 7/8/18.
//

#include <testRun.h>
#include <memory>
#include <iostream>

#include "testRun.h"

fbf::TestRun::TestRun(std::shared_ptr<fbf::FunctionIdentifier> test) :
    test_(test),
    test_has_run_(false),
    result_(std::numeric_limits<int>::max())
{

}

fbf::TestRun::~TestRun() = default;

void fbf::TestRun::run_test() {
    if(test_has_run_) {
        return;
    }

    test_has_run_ = true;
    result_ = test_->run_test();
}

void fbf::TestRun::output_results(std::ostream &out) {
    /* TODO: Implement a better version of this */
    if(!test_has_run_) {
        run_test();
    }

    out << "Result for 0x" << std::hex << test_->get_location() << ": " << result_;
}
