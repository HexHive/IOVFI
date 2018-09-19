//
// Created by derrick on 9/17/18.
//

#include <fosbin-sleuth/fullSleuthTest.h>
#include <fosbin-sleuth/argumentTestCase.h>

#include "fosbin-sleuth/fullSleuthTest.h"

#include <vector>
#include <map>
#include <cstring>

fbf::FullSleuthTest::FullSleuthTest(fs::path descriptor, int i, double d, size_t strLen, size_t ptrLen) :
        FullTest(descriptor), testInt(i), testDbl(d) {
    testStr = (char *) std::malloc(strLen);
    std::memset(testStr, 'A', strLen);
    std::strcpy(testStr, "THIS IS A TEST STRING!!!!");
    testPtr = std::malloc(ptrLen);
    for(size_t i = 0; i < ptrLen; i++) {
        ((char*)testPtr)[i] = rand();
    }

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

void fbf::FullSleuthTest::output(std::ostream &o) {
    std::map<uintptr_t, std::vector<std::shared_ptr<fbf::TestRun>>> successes;
    for(std::shared_ptr<fbf::TestRun> test : testRuns_) {
        if(test->get_result() == fbf::ITestCase::PASS) {
            if(successes.find(test->get_offset()) == successes.end()) {
                std::vector<std::shared_ptr<fbf::TestRun>> v;
                v.push_back(test);
                successes[test->get_offset()] = v;
            } else {
                successes[test->get_offset()].push_back(test);
            }
        }
    }

    for(auto it : successes) {
        o << "0x" << std::hex << it.first
        << std::dec << ": ";
        for(auto valid_args : it.second) {
            o << valid_args->get_test_name() << ", ";
        }
        o << std::endl;
    }
}

void fbf::FullSleuthTest::create_testcases() {
    for (uintptr_t offset : binDesc_.getOffsets()) {
        uintptr_t location = compute_location(offset);
        {
            std::tuple<> t;
            std::vector<std::string> l;
            std::shared_ptr<fbf::ArgumentTestCase<void>> v =
                    std::make_shared<fbf::ArgumentTestCase<void>>(location, t, l);
            testRuns_.push_back(std::make_shared<fbf::TestRun>(v, offset));
        }

#include "TestCases.inc"

    }
}
