//
// Created by derrick on 9/17/18.
//

#include <fosbin-sleuth/fullSleuthTest.h>
#include <fosbin-sleuth/argumentTestCase.h>

#include "fosbin-sleuth/fullSleuthTest.h"

fbf::FullSleuthTest::FullSleuthTest(fs::path descriptor, int i, double d, size_t strLen, size_t ptrLen) :
        FullTest(descriptor), testInt(i), testDbl(d) {
    testStr = (char *) std::malloc(strLen);
    testPtr = std::malloc(ptrLen);
    create_testcases();
}

fbf::FullSleuthTest::~FullSleuthTest() {
    if (testStr) {
        std::free(testStr);
    }

    if (testPtr) {
        std::free(testPtr);
    }
}

void fbf::FullSleuthTest::create_testcases() {
    for (uintptr_t offset : binDesc_.getOffsets()) {
        uintptr_t location = compute_location(offset);
        {
            std::tuple<> t;
            std::shared_ptr<fbf::ArgumentTestCase<void>> v = std::make_shared<fbf::ArgumentTestCase<void>>(location, t);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));
        }
        {
            std::tuple<int> t;
            std::get<0>(t) = testInt;
            std::shared_ptr<fbf::ArgumentTestCase<void, int>> v =
                    std::make_shared<fbf::ArgumentTestCase<void, int>>(location, t);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));
        }
    }
}
