//
// Created by derrick on 9/17/18.
//

#include <fosbin-sleuth/fullSleuthTest.h>
#include <fosbin-sleuth/argumentCountTestCase.h>
#include "fosbin-sleuth/fullSleuthTest.h"

#include <vector>
#include <map>
#include <cstring>
#include <random>
#include <limits>
#include <iterator>
#include <chrono>
#include <unistd.h>
#include <sys/mman.h>
#include <set>

fbf::FullSleuthTest::FullSleuthTest(fs::path descriptor, fs::path syscall_mapping, size_t strLen, size_t ptrLen,
                                    uint32_t thread_count) : FullTest(descriptor, syscall_mapping, thread_count) {
    init(strLen, ptrLen);
}

fbf::FullSleuthTest::FullSleuthTest(fs::path descriptor, size_t strLen, size_t ptrLen, uint32_t thread_count) :
        FullTest(descriptor, thread_count) {
    init(strLen, ptrLen);
}

void fbf::FullSleuthTest::init(size_t strLen, size_t ptrLen) {
    /* Avoid testInt values */
    std::uniform_int_distribution<uint8_t> charRand(MAX_ARGUMENTS + 2, 0xfe);
    std::uniform_int_distribution<int> intRand(std::numeric_limits<int>::min(),
                                               std::numeric_limits<int>::max());
    std::uniform_real_distribution<double> dblRand(std::numeric_limits<double>::min(),
                                                   std::numeric_limits<double>::max());
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::default_random_engine re(seed);

    for (size_t i = 0; i < MAX_ARGUMENTS; i++) {
        testInts.push_back(i + 2);
        testDbls.push_back(dblRand(re));

        testStrs.push_back((char *) std::malloc(strLen));
        testPtrs.push_back(ProtectedBuffer(ptrLen));

        for (size_t j = 0; j < strLen; j++) {
            /* Printable characters */
            char randChar = '!' + charRand(re) % ('~' - '!');
            testStrs[i][j] = randChar;
        }

        ProtectedBuffer buf = testPtrs[i];
        for (size_t j = 0; j < ptrLen; j++) {
            if (j < ptrLen - sizeof(wchar_t)) {
                buf[j] = charRand(re);
            } else {
                buf[j] = '\0';
            }
        }
    }

    create_testcases();
}

fbf::FullSleuthTest::~FullSleuthTest() {
    for (char *str : testStrs) {
        std::free(str);
    }
}

void fbf::FullSleuthTest::output(std::ostream &o) {
    for (std::shared_ptr<fbf::TestRun> test : testRuns_) {
        o << "Function " << binDesc_.getSym(test->get_location()).first;
        if (test->get_result() == fbf::ITestCase::PASS) {
            o << " has " << test->get_execution_result() << " argument";
            if (test->get_execution_result() != 1) {
                o << "s";
            }
            o << ".";
        } else {
            o << " CRASHED";
        }

        o << std::endl;
    }
}

void fbf::FullSleuthTest::create_testcases() {
    for (uintptr_t loc : binDesc_.getOffsets()) {
        uintptr_t location = compute_location(loc);
        std::pair<std::string, size_t> sym = binDesc_.getSym(location);

        std::shared_ptr<fbf::ArgumentCountTestCase> testcase = std::make_shared<fbf::ArgumentCountTestCase>(location,
                                                                                                            sym.second,
                                                                                                            binDesc_);
        testRuns_.push_back(std::make_shared<fbf::TestRun>(testcase, location));
    }
}
